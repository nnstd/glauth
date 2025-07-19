package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"slices"

	"github.com/rs/zerolog"
	"github.com/uptrace/opentelemetry-go-extra/otelsql"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/ldap"
	"github.com/nnstd/glauth/v2/pkg/config"
	"github.com/nnstd/glauth/v2/pkg/handler"
)

var configattributematcher = regexp.MustCompile(`(?i)\((?P<attribute>[a-zA-Z0-9]+)\s*=\s*(?P<value>.*)\)`)

type SqlBackend interface {
	// Name used by database/sql when loading the driver
	GetDriverName() string
	// Create db/schema if necessary
	CreateSchema(db *sql.DB)
	// Migrate schema if necessary
	MigrateSchema(db *sql.DB, checker func(*sql.DB, string, string) bool)
	//
	GetPrepareSymbol() string
}

type database struct {
	path string
	cnx  *sql.DB
}

type databaseHandler struct {
	backend     config.Backend
	log         *zerolog.Logger
	cfg         *config.Config
	yubikeyAuth *yubigo.YubiAuth

	sqlBackend     SqlBackend
	preparedSymbol string

	database   database
	MemGroups  []config.Group
	ldohelper  handler.LDAPOpsHelper
	attmatcher *regexp.Regexp

	tracer trace.Tracer
}

func NewDatabaseHandler(sqlBackend SqlBackend, opts ...handler.Option) handler.Handler {
	options := handler.NewOptions(opts...)

	// Note: we will never terminate this connection pool.
	db, err := otelsql.Open(
		sqlBackend.GetDriverName(),
		options.Backend.Database,
		otelsql.WithAttributes(otlpDriverAttribute(sqlBackend)),
		otelsql.WithDBName(options.Backend.Database),
	)
	if err != nil {
		options.Logger.Error().Err(err).Msg(fmt.Sprintf("unable to open SQL database named '%s'", options.Backend.Database))
		os.Exit(1)
	}

	err = db.Ping()
	if err != nil {
		options.Logger.Error().Err(err).Msg(fmt.Sprintf("unable to communicate with SQL database error: %s", options.Backend.Database))
		os.Exit(1)
	}

	dbInfo := database{
		path: options.Backend.Database,
		cnx:  db,
	}

	handler := databaseHandler{
		backend:     options.Backend,
		log:         options.Logger,
		cfg:         options.Config,
		yubikeyAuth: options.YubiAuth,
		sqlBackend:  sqlBackend,
		database:    dbInfo,
		ldohelper:   options.LDAPHelper,
		attmatcher:  configattributematcher,
		tracer:      options.Tracer,
	}

	sqlBackend.CreateSchema(db)
	sqlBackend.MigrateSchema(db, ColumnExists)

	handler.preparedSymbol = sqlBackend.GetPrepareSymbol()

	options.Logger.Debug().Msg("Database handler is ready")

	return handler
}

func ColumnExists(db *sql.DB, tableName string, columnName string) bool {
	var found string
	err := db.QueryRowContext(context.Background(), fmt.Sprintf(`SELECT COUNT(%s) FROM %s`, columnName, tableName)).Scan(
		&found)
	return err == nil
}

func otlpDriverAttribute(backend SqlBackend) attribute.KeyValue {
	switch backend.GetDriverName() {
	case "sqlite3":
		return semconv.DBSystemSqlite
	case "postgres":
		return semconv.DBSystemPostgreSQL
	case "mysql":
		return semconv.DBSystemMySQL
	default:
		return semconv.DBSystemOtherSQL
	}
}

func (h databaseHandler) GetBackend() config.Backend {
	return h.backend
}

func (h databaseHandler) GetLog() *zerolog.Logger {
	return h.log
}

func (h databaseHandler) GetCfg() *config.Config {
	return h.cfg
}

func (h databaseHandler) GetYubikeyAuth() *yubigo.YubiAuth {
	return h.yubikeyAuth
}

func (h databaseHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	ctx, span := h.tracer.Start(context.Background(), "database.databaseHandler.Bind")
	defer span.End()

	return h.ldohelper.Bind(ctx, h, bindDN, bindSimplePw, conn)
}

func (h databaseHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	ctx, span := h.tracer.Start(context.Background(), "database.databaseHandler.Search")
	defer span.End()

	return h.ldohelper.Search(ctx, h, bindDN, searchReq, conn)
}

// Add is not yet supported for the sql backend
func (h databaseHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "database.databaseHandler.Add")
	defer span.End()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not yet supported for the sql backend
func (h databaseHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "database.databaseHandler.Modify")
	defer span.End()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not yet supported for the sql backend
func (h databaseHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "database.databaseHandler.Delete")
	defer span.End()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Close does nothing.
func (h databaseHandler) Close(boundDN string, conn net.Conn) error {
	return nil
}

func (h databaseHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (f bool, u config.User, err error) {
	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.FindUser")
	defer span.End()

	user := config.User{}
	found := false

	var query string
	if searchByUPN {
		if h.cfg.Behaviors.LegacyVersion < 20231 {
			// For legacy version, if UPN flag is set, search explicitly within the mail field
			query = fmt.Sprintf(`
				SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups,u.givenname,u.sn,u.mail,u.loginshell,u.homedirectory,u.disabled,u.sshkeys,u.custattr
				FROM users u 
				WHERE LOWER(u.mail)=%s`,
				h.preparedSymbol,
			)
		} else {
			// For newer versions, UPN flag means "search name first, then email"
			query = fmt.Sprintf(`
				SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups,u.givenname,u.sn,u.mail,u.loginshell,u.homedirectory,u.disabled,u.sshkeys,u.custattr
				FROM users u 
				WHERE lower(u.name)=%s OR lower(u.mail)=%s`,
				h.preparedSymbol,
				h.preparedSymbol,
			)
		}
	} else {
		query = fmt.Sprintf(`
			SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups,u.givenname,u.sn,u.mail,u.loginshell,u.homedirectory,u.disabled,u.sshkeys,u.custattr
			FROM users u 
			WHERE lower(u.name)=%s`,
			h.preparedSymbol,
		)
	}

	h.log.Debug().Str("query", query).Str("userName", userName).Msg("FindUser query")

	var otherGroups string
	var disabled int
	var sshKeys string
	var custattrstr string
	var passBcrypt, passSHA256, otpSecret, yubikey, givenName, sn, mail, loginShell, homedir sql.NullString

	searchTerm := strings.ToLower(userName)
	var err2 error

	if searchByUPN && h.cfg.Behaviors.LegacyVersion >= 20231 {
		err2 = h.database.cnx.QueryRowContext(
			ctx,
			query,
			searchTerm, searchTerm,
		).Scan(&user.Name, &user.UIDNumber, &user.PrimaryGroup, &passBcrypt, &passSHA256, &otpSecret, &yubikey, &otherGroups, &givenName, &sn, &mail, &loginShell, &homedir, &disabled, &sshKeys, &custattrstr)
	} else {
		err2 = h.database.cnx.QueryRowContext(
			ctx,
			query,
			searchTerm,
		).Scan(&user.Name, &user.UIDNumber, &user.PrimaryGroup, &passBcrypt, &passSHA256, &otpSecret, &yubikey, &otherGroups, &givenName, &sn, &mail, &loginShell, &homedir, &disabled, &sshKeys, &custattrstr)
	}

	// Initialize capabilities to empty slice by default
	user.Capabilities = []config.Capability{}

	if err2 == nil {
		found = true

		// Convert sql.NullString to regular strings
		if passBcrypt.Valid {
			user.PassBcrypt = passBcrypt.String
		}
		if passSHA256.Valid {
			user.PassSHA256 = passSHA256.String
		}
		if otpSecret.Valid {
			user.OTPSecret = otpSecret.String
		}
		if yubikey.Valid {
			user.Yubikey = yubikey.String
		}
		if givenName.Valid {
			user.GivenName = givenName.String
		}
		if sn.Valid {
			user.SN = sn.String
		}
		if mail.Valid {
			user.Mail = mail.String
		}
		if loginShell.Valid {
			user.LoginShell = loginShell.String
		}
		if homedir.Valid {
			user.Homedir = homedir.String
		}

		if disabled == 1 {
			user.Disabled = true
		}

		// Convert comma-separated groups to slice of ints
		user.OtherGroups = h.commaListToIntTable(ctx, otherGroups)

		// Parse custom attributes JSON
		user.CustomAttrs = make(map[string]interface{})
		if custattrstr != "" {
			json.Unmarshal([]byte(custattrstr), &user.CustomAttrs)
		}

		// Parse SSH keys
		if sshKeys != "" {
			user.SSHKeys = strings.Split(sshKeys, "\n")
		}

		// Query capabilities for this user using JOIN for better performance
		capQuery := fmt.Sprintf(`
			SELECT c.action, c.object 
			FROM capabilities c 
			JOIN users u ON c.userid = u.id 
			WHERE u.name = %s`, h.preparedSymbol)

		h.log.Debug().Str("query", capQuery).Str("userName", user.Name).Msg("FindUser capabilities query")

		capRows, capErr := h.database.cnx.QueryContext(ctx, capQuery, user.Name)
		if capErr == nil {
			defer capRows.Close()
			for capRows.Next() {
				var capability config.Capability
				scanErr := capRows.Scan(&capability.Action, &capability.Object)
				if scanErr == nil {
					user.Capabilities = append(user.Capabilities, capability)
				}
			}
		} else {
			h.log.Error().Err(capErr).Msg("FindUser capabilities query failed")
		}

		// Note: If capabilities query fails, we keep the empty slice initialized above
	}

	return found, user, err2
}

func (h databaseHandler) FindGroup(ctx context.Context, groupName string) (f bool, g config.Group, err error) {
	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.FindGroup")
	defer span.End()

	group := config.Group{}
	found := false

	query := fmt.Sprintf(`
		SELECT g.gidnumber FROM ldapgroups g WHERE lower(name)=%s`,
		h.preparedSymbol,
	)

	h.log.Debug().Str("query", query).Str("groupName", groupName).Msg("FindGroup query")

	err = h.database.cnx.QueryRowContext(
		ctx,
		query,
		groupName,
	).Scan(&group.GIDNumber)

	if err == nil {
		found = true
	}

	return found, group, err
}

func (h databaseHandler) FindPosixAccounts(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.FindPosixAccounts")
	defer span.End()

	entries := []*ldap.Entry{}

	h.MemGroups, err = h.memoizeGroups(ctx)
	if err != nil {
		return entries, err
	}

	rows, err := h.database.cnx.QueryContext(
		ctx,
		`SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups,u.givenname,u.sn,u.mail,u.loginshell,u.homedirectory,u.disabled,u.sshkeys,u.custattr  
		FROM users u`)
	if err != nil {
		return entries, err
	}
	defer rows.Close()

	var otherGroups string
	var disabled int
	var sshKeys string
	var custattrstr string
	var passBcrypt, passSHA256, otpSecret, yubikey, givenName, sn, mail, loginShell, homedir sql.NullString

	u := config.User{}

	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UIDNumber, &u.PrimaryGroup, &passBcrypt, &passSHA256, &otpSecret, &yubikey, &otherGroups, &givenName, &sn, &mail, &loginShell, &homedir, &disabled, &sshKeys, &custattrstr)
		if err != nil {
			return entries, err
		}

		// Convert sql.NullString to regular strings
		if passBcrypt.Valid {
			u.PassBcrypt = passBcrypt.String
		}

		if passSHA256.Valid {
			u.PassSHA256 = passSHA256.String
		}

		if otpSecret.Valid {
			u.OTPSecret = otpSecret.String
		}

		if yubikey.Valid {
			u.Yubikey = yubikey.String
		}

		if givenName.Valid {
			u.GivenName = givenName.String
		}

		if sn.Valid {
			u.SN = sn.String
		}

		if mail.Valid {
			u.Mail = mail.String
		}

		if loginShell.Valid {
			u.LoginShell = loginShell.String
		}

		if homedir.Valid {
			u.Homedir = homedir.String
		}

		if disabled == 1 {
			u.Disabled = true
		}

		u.OtherGroups = h.commaListToIntTable(ctx, otherGroups)

		// Parse custom attributes JSON
		u.CustomAttrs = make(map[string]interface{})
		if custattrstr != "" {
			json.Unmarshal([]byte(custattrstr), &u.CustomAttrs)
		}

		// Parse SSH keys
		if sshKeys != "" {
			u.SSHKeys = strings.Split(sshKeys, "\n")
		}

		attrs := []*ldap.EntryAttribute{}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{u.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{u.Name}})

		if u.UIDNumber != 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{fmt.Sprintf("%d", u.UIDNumber)}})
		}
		if u.PrimaryGroup != 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", u.PrimaryGroup)}})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount", "shadowAccount"}})

		if u.GivenName != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{u.GivenName}})
		}

		if u.SN != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "sn", Values: []string{u.SN}})
		}

		if u.Mail != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{u.Mail}})
		}

		if u.LoginShell != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{u.LoginShell}})
		}

		if u.Homedir != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{u.Homedir}})
		}

		if len(u.SSHKeys) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: h.backend.SSHKeyAttr, Values: u.SSHKeys})
		}

		// Handle custom attributes
		for key, value := range u.CustomAttrs {
			if valStr, ok := value.(string); ok {
				attrs = append(attrs, &ldap.EntryAttribute{Name: key, Values: []string{valStr}})
			}
		}

		var insertOuUsers string
		if h.cfg.Behaviors.LegacyVersion > 0 && h.cfg.Behaviors.LegacyVersion <= 20100 {
			insertOuUsers = ""
		} else {
			insertOuUsers = ",ou=users"
		}

		dn := fmt.Sprintf("%s=%s,%s=%s%s,%s", h.backend.NameFormatAsArray[0], u.Name, h.backend.GroupFormatAsArray[0], h.getGroupName(ctx, u.PrimaryGroup), insertOuUsers, h.backend.BaseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	h.log.Debug().Int("users_found", len(entries)).Msg("Users found")

	return entries, nil
}

func (h databaseHandler) FindPosixGroups(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.FindPosixGroups")
	defer span.End()

	entries := []*ldap.Entry{}

	h.MemGroups, err = h.memoizeGroups(ctx)
	if err != nil {
		return entries, err
	}

	for _, g := range h.MemGroups {
		attrs := []*ldap.EntryAttribute{}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{g.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s via LDAP", g.Name)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", g.GIDNumber)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: h.getGroupMemberNames(ctx, g.GIDNumber)})

		var insertOuUsers string
		if h.cfg.Behaviors.LegacyVersion > 0 && h.cfg.Behaviors.LegacyVersion <= 20100 {
			insertOuUsers = ""
		} else {
			insertOuUsers = ",ou=users"
		}

		dn := fmt.Sprintf("%s=%s%s,%s", h.backend.GroupFormatAsArray[0], g.Name, insertOuUsers, h.backend.BaseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	h.log.Debug().Int("groups_found", len(entries)).Msg("Groups found")

	return entries, nil
}

func (h databaseHandler) getGroupMemberDNs(ctx context.Context, gid int) []string {
	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.getGroupMemberDNs")
	defer span.End()

	var insertOuUsers string
	if h.cfg.Behaviors.LegacyVersion > 0 && h.cfg.Behaviors.LegacyVersion <= 20100 {
		insertOuUsers = ""
	} else {
		insertOuUsers = ",ou=users"
	}
	members := make(map[string]bool)

	rows, err := h.database.cnx.QueryContext(
		ctx,
		`SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups
		FROM users u`)
	if err != nil {
		// Silent fail... for now
		return []string{}
	}

	defer rows.Close()

	var otherGroups string
	var passBcrypt, passSHA256, otpSecret, yubikey sql.NullString

	u := config.User{}

	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UIDNumber, &u.PrimaryGroup, &passBcrypt, &passSHA256, &otpSecret, &yubikey, &otherGroups)
		if err != nil {
			return []string{}
		}

		// Convert sql.NullString to regular strings
		if passBcrypt.Valid {
			u.PassBcrypt = passBcrypt.String
		}

		if passSHA256.Valid {
			u.PassSHA256 = passSHA256.String
		}

		if otpSecret.Valid {
			u.OTPSecret = otpSecret.String
		}

		if yubikey.Valid {
			u.Yubikey = yubikey.String
		}

		if u.PrimaryGroup == gid {
			dn := fmt.Sprintf("%s=%s,%s=%s%s,%s", h.backend.NameFormatAsArray[0], u.Name, h.backend.GroupFormatAsArray[0], h.getGroupName(ctx, u.PrimaryGroup), insertOuUsers, h.backend.BaseDN)
			members[dn] = true
		} else {
			u.OtherGroups = h.commaListToIntTable(ctx, otherGroups)
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					dn := fmt.Sprintf("%s=%s,%s=%s%s,%s", h.backend.NameFormatAsArray[0], u.Name, h.backend.GroupFormatAsArray[0], h.getGroupName(ctx, u.PrimaryGroup), insertOuUsers, h.backend.BaseDN)
					members[dn] = true
				}
			}
		}
	}

	var retval []string
	for member := range members {
		retval = append(retval, member)
	}

	slices.Sort(retval)

	return retval
}

func (h databaseHandler) getGroupMemberNames(ctx context.Context, gid int) []string {
	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.getGroupMemberNames")
	defer span.End()

	members := make(map[string]bool)

	rows, err := h.database.cnx.QueryContext(
		ctx,
		`SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups
		FROM users u`,
	)
	if err != nil {
		// Silent fail... for now
		return []string{}
	}

	defer rows.Close()

	var otherGroups string
	var passBcrypt, passSHA256, otpSecret, yubikey sql.NullString

	u := config.User{}

	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UIDNumber, &u.PrimaryGroup, &passBcrypt, &passSHA256, &otpSecret, &yubikey, &otherGroups)
		if err != nil {
			return []string{}
		}

		// Convert sql.NullString to regular strings
		if passBcrypt.Valid {
			u.PassBcrypt = passBcrypt.String
		}

		if passSHA256.Valid {
			u.PassSHA256 = passSHA256.String
		}

		if otpSecret.Valid {
			u.OTPSecret = otpSecret.String
		}

		if yubikey.Valid {
			u.Yubikey = yubikey.String
		}

		if u.PrimaryGroup == gid {
			members[u.Name] = true
		} else {
			u.OtherGroups = h.commaListToIntTable(ctx, otherGroups)
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					members[u.Name] = true
				}
			}
		}
	}

	var retval []string
	for member := range members {
		retval = append(retval, member)
	}

	slices.Sort(retval)

	return retval
}

func (h databaseHandler) getGroupName(ctx context.Context, gid int) string {
	_, span := h.tracer.Start(ctx, "database.databaseHandler.getGroupName")
	defer span.End()

	for _, g := range h.MemGroups {
		if g.GIDNumber == gid {
			return g.Name
		}
	}

	return ""
}

func (h databaseHandler) memoizeGroups(ctx context.Context) ([]config.Group, error) {
	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.memoizeGroups")
	defer span.End()

	var groups []config.Group

	rows, err := h.database.cnx.QueryContext(ctx, "SELECT name, gidnumber FROM ldapgroups")
	if err != nil {
		return groups, err
	}
	defer rows.Close()

	for rows.Next() {
		var g config.Group
		err := rows.Scan(&g.Name, &g.GIDNumber)
		if err != nil {
			return groups, err
		}
		groups = append(groups, g)
	}

	return groups, nil
}

func (h databaseHandler) commaListToIntTable(ctx context.Context, commaList string) []int {
	_, span := h.tracer.Start(ctx, "database.databaseHandler.commaListToIntTable")
	defer span.End()

	var intTable []int
	if commaList == "" {
		return intTable
	}

	for _, stringGroup := range strings.Split(commaList, ",") {
		trimmed := strings.TrimSpace(stringGroup)
		if trimmed != "" {
			if converted, err := strconv.Atoi(trimmed); err == nil {
				intTable = append(intTable, converted)
			}
		}
	}

	return intTable
}
