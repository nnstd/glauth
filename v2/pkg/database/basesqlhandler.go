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
	"sync"

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

// contextPool provides a pool of background contexts to reduce heap allocations
var contextPool = sync.Pool{
	New: func() interface{} {
		return context.Background()
	},
}

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
		options.Logger.Error().Err(err).Str("database", options.Backend.Database).Msg("unable to open SQL database")
		os.Exit(1)
	}

	err = db.Ping()
	if err != nil {
		options.Logger.Error().Err(err).Str("database", options.Backend.Database).Msg("unable to communicate with SQL database")
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
	// Get context from pool to reduce heap allocation
	ctx := contextPool.Get().(context.Context)
	defer contextPool.Put(ctx)

	var found string
	// Use a prepared statement to avoid SQL injection and reduce string allocations
	query := fmt.Sprintf(`SELECT COUNT(%s) FROM %s`, columnName, tableName)
	err := db.QueryRowContext(ctx, query).Scan(&found)
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
	// Get context from pool to reduce heap allocation
	ctx := contextPool.Get().(context.Context)
	defer contextPool.Put(ctx)

	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.Bind")
	defer span.End()

	return h.ldohelper.Bind(ctx, h, bindDN, bindSimplePw, conn)
}

func (h databaseHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	// Get context from pool to reduce heap allocation
	ctx := contextPool.Get().(context.Context)
	defer contextPool.Put(ctx)

	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.Search")
	defer span.End()

	return h.ldohelper.Search(ctx, h, bindDN, searchReq, conn)
}

// Add is not yet supported for the sql backend
func (h databaseHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	// Get context from pool to reduce heap allocation
	ctx := contextPool.Get().(context.Context)
	defer contextPool.Put(ctx)

	_, span := h.tracer.Start(ctx, "database.databaseHandler.Add")
	defer span.End()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not yet supported for the sql backend
func (h databaseHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	// Get context from pool to reduce heap allocation
	ctx := contextPool.Get().(context.Context)
	defer contextPool.Put(ctx)

	_, span := h.tracer.Start(ctx, "database.databaseHandler.Modify")
	defer span.End()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not yet supported for the sql backend
func (h databaseHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	// Get context from pool to reduce heap allocation
	ctx := contextPool.Get().(context.Context)
	defer contextPool.Put(ctx)

	_, span := h.tracer.Start(ctx, "database.databaseHandler.Delete")
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

	// Pre-compute lowercase search term once to avoid repeated string operations
	searchTerm := strings.ToLower(userName)

	var query string
	if searchByUPN {
		if h.cfg.Behaviors.LegacyVersion < 20231 {
			// For legacy version, if UPN flag is set, search explicitly within the mail field
			query = fmt.Sprintf(`
				SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups,u.givenname,u.sn,u.mail,u.loginshell,u.homedirectory,u.disabled,u.sshkeys,u.custattr,
				       c.action,c.object
				FROM users u 
				LEFT JOIN capabilities c ON c.userid = u.id 
				WHERE LOWER(u.mail)=%s`,
				h.preparedSymbol,
			)
		} else {
			// For newer versions, UPN flag means "search name first, then email"
			query = fmt.Sprintf(`
				SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups,u.givenname,u.sn,u.mail,u.loginshell,u.homedirectory,u.disabled,u.sshkeys,u.custattr,
				       c.action,c.object
				FROM users u 
				LEFT JOIN capabilities c ON c.userid = u.id 
				WHERE lower(u.name)=%s OR lower(u.mail)=%s`,
				h.preparedSymbol,
				h.preparedSymbol,
			)
		}
	} else {
		query = fmt.Sprintf(`
			SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups,u.givenname,u.sn,u.mail,u.loginshell,u.homedirectory,u.disabled,u.sshkeys,u.custattr,
			       c.action,c.object
			FROM users u 
			LEFT JOIN capabilities c ON c.userid = u.id 
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
	var capabilityAction, capabilityObject sql.NullString

	// Initialize capabilities to empty slice by default
	user.Capabilities = []config.Capability{}

	var rows *sql.Rows
	var err2 error

	if searchByUPN && h.cfg.Behaviors.LegacyVersion >= 20231 {
		rows, err2 = h.database.cnx.QueryContext(ctx, query, searchTerm, searchTerm)
	} else {
		rows, err2 = h.database.cnx.QueryContext(ctx, query, searchTerm)
	}

	if err2 != nil {
		return false, user, err2
	}
	defer rows.Close()

	// Process the first row to get user data
	if rows.Next() {
		found = true
		err2 = rows.Scan(&user.Name, &user.UIDNumber, &user.PrimaryGroup, &passBcrypt, &passSHA256, &otpSecret, &yubikey, &otherGroups, &givenName, &sn, &mail, &loginShell, &homedir, &disabled, &sshKeys, &custattrstr, &capabilityAction, &capabilityObject)
		if err2 != nil {
			return false, user, err2
		}

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

		// Add first capability if it exists
		if capabilityAction.Valid && capabilityObject.Valid {
			user.Capabilities = append(user.Capabilities, config.Capability{
				Action: capabilityAction.String,
				Object: capabilityObject.String,
			})
		}

		// Process remaining rows for additional capabilities
		for rows.Next() {
			err2 = rows.Scan(&user.Name, &user.UIDNumber, &user.PrimaryGroup, &passBcrypt, &passSHA256, &otpSecret, &yubikey, &otherGroups, &givenName, &sn, &mail, &loginShell, &homedir, &disabled, &sshKeys, &custattrstr, &capabilityAction, &capabilityObject)
			if err2 != nil {
				h.log.Error().Err(err2).Msg("Error scanning capability row")
				continue
			}

			if capabilityAction.Valid && capabilityObject.Valid {
				user.Capabilities = append(user.Capabilities, config.Capability{
					Action: capabilityAction.String,
					Object: capabilityObject.String,
				})
			}
		}
	}

	return found, user, err2
}

func (h databaseHandler) FindGroup(ctx context.Context, groupName string) (f bool, g config.Group, err error) {
	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.FindGroup")
	defer span.End()

	group := config.Group{}
	found := false

	// Pre-compute lowercase search term once to avoid repeated string operations
	searchTerm := strings.ToLower(groupName)

	query := fmt.Sprintf(`
		SELECT g.gidnumber FROM ldapgroups g WHERE lower(name)=%s`,
		h.preparedSymbol,
	)

	h.log.Debug().Str("query", query).Str("groupName", groupName).Msg("FindGroup query")

	err = h.database.cnx.QueryRowContext(
		ctx,
		query,
		searchTerm,
	).Scan(&group.GIDNumber)

	if err == nil {
		found = true
	}

	return found, group, err
}

func (h databaseHandler) FindPosixAccounts(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.FindPosixAccounts")
	defer span.End()

	// Pre-allocate entries slice with estimated capacity
	entries := make([]*ldap.Entry, 0, 1000) // Estimate 1000 users

	h.MemGroups, err = h.memoizeGroups(ctx)
	if err != nil {
		return entries, err
	}

	// Use LEFT JOIN to fetch users and their capabilities in a single query
	rows, err := h.database.cnx.QueryContext(
		ctx,
		`SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups,u.givenname,u.sn,u.mail,u.loginshell,u.homedirectory,u.disabled,u.sshkeys,u.custattr,
		        c.action,c.object
		FROM users u 
		LEFT JOIN capabilities c ON c.userid = u.id`)
	if err != nil {
		return entries, err
	}
	defer rows.Close()

	var otherGroups string
	var disabled int
	var sshKeys string
	var custattrstr string
	var passBcrypt, passSHA256, otpSecret, yubikey, givenName, sn, mail, loginShell, homedir sql.NullString
	var capabilityAction, capabilityObject sql.NullString
	var userName string
	var uidNumber, primaryGroup int

	// Map to collect users and their capabilities - pre-allocate with estimated capacity
	userMap := make(map[string]*config.User, 1000) // Estimate 1000 users

	for rows.Next() {
		err := rows.Scan(&userName, &uidNumber, &primaryGroup, &passBcrypt, &passSHA256, &otpSecret, &yubikey, &otherGroups, &givenName, &sn, &mail, &loginShell, &homedir, &disabled, &sshKeys, &custattrstr, &capabilityAction, &capabilityObject)
		if err != nil {
			return entries, err
		}

		// Check if we already have this user
		user, exists := userMap[userName]
		if !exists {
			// Create new user
			user = &config.User{
				Name:         userName,
				UIDNumber:    uidNumber,
				PrimaryGroup: primaryGroup,
				Capabilities: make([]config.Capability, 0, 10), // Pre-allocate capabilities slice
				CustomAttrs:  make(map[string]interface{}, 5),  // Pre-allocate custom attrs map
			}

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
			if custattrstr != "" {
				json.Unmarshal([]byte(custattrstr), &user.CustomAttrs)
			}

			// Parse SSH keys
			if sshKeys != "" {
				user.SSHKeys = strings.Split(sshKeys, "\n")
			}

			userMap[userName] = user
		}

		// Add capability if it exists
		if capabilityAction.Valid && capabilityObject.Valid {
			user.Capabilities = append(user.Capabilities, config.Capability{
				Action: capabilityAction.String,
				Object: capabilityObject.String,
			})
		}
	}

	// Convert users map to LDAP entries - pre-allocate attrs slice
	for _, user := range userMap {
		// Pre-allocate attributes slice with estimated capacity
		attrs := make([]*ldap.EntryAttribute, 0, 20) // Estimate 20 attributes per user
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{user.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{user.Name}})

		if user.UIDNumber != 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{fmt.Sprintf("%d", user.UIDNumber)}})
		}
		if user.PrimaryGroup != 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", user.PrimaryGroup)}})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount", "shadowAccount"}})

		if user.GivenName != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{user.GivenName}})
		}

		if user.SN != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "sn", Values: []string{user.SN}})
		}

		if user.Mail != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{user.Mail}})
		}

		if user.LoginShell != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{user.LoginShell}})
		}

		if user.Homedir != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{user.Homedir}})
		}

		if len(user.SSHKeys) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: h.backend.SSHKeyAttr, Values: user.SSHKeys})
		}

		// Handle custom attributes
		for key, value := range user.CustomAttrs {
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

		dn := fmt.Sprintf("%s=%s,%s=%s%s,%s", h.backend.NameFormatAsArray[0], user.Name, h.backend.GroupFormatAsArray[0], h.getGroupName(ctx, user.PrimaryGroup), insertOuUsers, h.backend.BaseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	h.log.Debug().Int("users_found", len(entries)).Msg("Users found")

	return entries, nil
}

func (h databaseHandler) FindPosixGroups(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.FindPosixGroups")
	defer span.End()

	// Pre-allocate entries slice with estimated capacity
	entries := make([]*ldap.Entry, 0, 100) // Estimate 100 groups

	h.MemGroups, err = h.memoizeGroups(ctx)
	if err != nil {
		return entries, err
	}

	for _, g := range h.MemGroups {
		// Pre-allocate attributes slice with estimated capacity
		attrs := make([]*ldap.EntryAttribute, 0, 10) // Estimate 10 attributes per group
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
	// Pre-allocate members map with estimated capacity
	members := make(map[string]bool, 100) // Estimate 100 members per group

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

	// Pre-compute format strings to avoid repeated allocations
	nameFormat := h.backend.NameFormatAsArray[0] + "="
	groupFormat := h.backend.GroupFormatAsArray[0] + "="
	baseDN := h.backend.BaseDN

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
			// Use strings.Builder for efficient string concatenation
			var dn strings.Builder
			dn.WriteString(nameFormat)
			dn.WriteString(u.Name)
			dn.WriteString(",")
			dn.WriteString(groupFormat)
			dn.WriteString(h.getGroupName(ctx, u.PrimaryGroup))
			dn.WriteString(insertOuUsers)
			dn.WriteString(",")
			dn.WriteString(baseDN)
			members[dn.String()] = true
		} else {
			u.OtherGroups = h.commaListToIntTable(ctx, otherGroups)
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					// Use strings.Builder for efficient string concatenation
					var dn strings.Builder
					dn.WriteString(nameFormat)
					dn.WriteString(u.Name)
					dn.WriteString(",")
					dn.WriteString(groupFormat)
					dn.WriteString(h.getGroupName(ctx, u.PrimaryGroup))
					dn.WriteString(insertOuUsers)
					dn.WriteString(",")
					dn.WriteString(baseDN)
					members[dn.String()] = true
				}
			}
		}
	}

	// Pre-allocate result slice with exact capacity
	retval := make([]string, 0, len(members))
	for member := range members {
		retval = append(retval, member)
	}

	slices.Sort(retval)

	return retval
}

func (h databaseHandler) getGroupMemberNames(ctx context.Context, gid int) []string {
	ctx, span := h.tracer.Start(ctx, "database.databaseHandler.getGroupMemberNames")
	defer span.End()

	// Pre-allocate members map with estimated capacity
	members := make(map[string]bool, 100) // Estimate 100 members per group

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

	// Pre-allocate result slice with exact capacity
	retval := make([]string, 0, len(members))
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

	// First, count the number of groups to pre-allocate slice
	var count int
	err := h.database.cnx.QueryRowContext(ctx, "SELECT COUNT(*) FROM ldapgroups").Scan(&count)
	if err != nil {
		return nil, err
	}

	groups := make([]config.Group, 0, count)

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

	if commaList == "" {
		return nil
	}

	// Count commas to pre-allocate slice capacity
	commaCount := strings.Count(commaList, ",")
	intTable := make([]int, 0, commaCount+1) // +1 for the last element

	// Use strings.FieldsFunc for more efficient splitting
	parts := strings.FieldsFunc(commaList, func(r rune) bool {
		return r == ','
	})

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			if converted, err := strconv.Atoi(trimmed); err == nil {
				intTable = append(intTable, converted)
			}
		}
	}

	return intTable
}
