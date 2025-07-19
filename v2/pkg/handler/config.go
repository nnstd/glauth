package handler

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/ldap"
	"github.com/nnstd/glauth/v2/internal/monitoring"
	"github.com/nnstd/glauth/v2/pkg/config"
	"github.com/nnstd/glauth/v2/pkg/stats"
)

type configHandler struct {
	backend     config.Backend
	log         *zerolog.Logger
	cfg         *config.Config
	yubikeyAuth *yubigo.YubiAuth
	ldohelper   LDAPOpsHelper
	attmatcher  *regexp.Regexp

	monitor monitoring.MonitorInterface
	tracer  trace.Tracer
}

// NewConfigHandler creates a new config backed handler
func NewConfigHandler(opts ...Option) Handler {
	options := newOptions(opts...)

	handler := configHandler{
		backend:     options.Backend,
		log:         options.Logger,
		cfg:         options.Config, // TODO only used to access Users and Groups, move that to dedicated options
		yubikeyAuth: options.YubiAuth,
		ldohelper:   options.LDAPHelper,
		attmatcher:  configattributematcher,
		monitor:     options.Monitor,
		tracer:      options.Tracer,
	}

	handler.log.Debug().Msg("ConfigHandler created")

	return handler
}

func (h configHandler) GetBackend() config.Backend {
	return h.backend
}

func (h configHandler) GetLog() *zerolog.Logger {
	return h.log
}

func (h configHandler) GetCfg() *config.Config {
	return h.cfg
}

func (h configHandler) GetYubikeyAuth() *yubigo.YubiAuth {
	return h.yubikeyAuth
}

// Bind implements a bind request against the config file
func (h configHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	ctx, span := h.tracer.Start(context.Background(), "handler.configHandler.Bind")
	defer span.End()

	h.log.Debug().Str("bindDN", bindDN).Str("bindSimplePw", bindSimplePw).Msg("Bind")

	start := time.Now()

	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "bind", "status": fmt.Sprintf("%v", result)},
			time.Since(start).Seconds(),
		)
	}()

	return h.ldohelper.Bind(ctx, h, bindDN, bindSimplePw, conn)
}

// Search implements a search request against the config file
func (h configHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	ctx, span := h.tracer.Start(context.Background(), "handler.configHandler.Search")
	defer span.End()

	h.log.Debug().Str("bindDN", bindDN).Msg("Search")

	start := time.Now()

	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "search", "status": fmt.Sprintf("%v", result.ResultCode)},
			time.Since(start).Seconds(),
		)
	}()

	return h.ldohelper.Search(ctx, h, bindDN, searchReq, conn)
}

// Add is not supported for a static config file
func (h configHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "handler.configHandler.Add")
	defer span.End()

	h.log.Debug().Str("boundDN", boundDN).Msg("Add")

	start := time.Now()

	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "add", "status": fmt.Sprintf("%v", result)},
			time.Since(start).Seconds(),
		)
	}()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not supported for a static config file
func (h configHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "handler.configHandler.Modify")
	defer span.End()

	h.log.Debug().Str("boundDN", boundDN).Msg("Modify")

	start := time.Now()

	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "modify", "status": fmt.Sprintf("%v", result)},
			time.Since(start).Seconds(),
		)
	}()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not supported for a static config file
func (h configHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "handler.configHandler.Delete")
	defer span.End()

	h.log.Debug().Str("boundDN", boundDN).Str("deleteDN", deleteDN).Msg("Delete")

	start := time.Now()

	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "delete", "status": fmt.Sprintf("%v", result)},
			time.Since(start).Seconds(),
		)
	}()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h configHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (f bool, u config.User, err error) {
	_, span := h.tracer.Start(ctx, "handler.configHandler.FindUser")
	defer span.End()

	h.log.Info().Int("users", len(h.cfg.Users)).Msg("users in FindUser")
	h.log.Debug().Str("userName", userName).Bool("searchByUPN", searchByUPN).Msg("need find in FindUser")

	user := config.User{}
	found := false

	h.log.Debug().Int("users", len(h.cfg.Users)).Msg("users in FindUser")

	for _, u := range h.cfg.Users {
		h.log.Debug().Str("userName", userName).Msg("found user in FindUser")

		if searchByUPN {
			if strings.EqualFold(u.Mail, userName) {
				h.log.Debug().Str("userName", userName).Msg("upn match in FindUser")

				found = true
				user = u
			} else {
				h.log.Debug().Str("userName", userName).Msg("upn not match in FindUser")
			}
		} else {
			if strings.EqualFold(u.Name, userName) {
				h.log.Debug().Str("userName", userName).Msg("name match in FindUser")

				found = true
				user = u
			} else {
				h.log.Debug().Str("userName", userName).Msg("name not match in FindUser")
			}
		}
	}

	return found, user, nil
}

func (h configHandler) FindGroup(ctx context.Context, groupName string) (f bool, g config.Group, err error) {
	_, span := h.tracer.Start(ctx, "handler.configHandler.FindGroup")
	defer span.End()

	h.log.Debug().Str("groupName", groupName).Msg("FindGroup")

	fillGroup := config.Group{}

	found := false

	for _, group := range h.cfg.Groups {
		h.log.Debug().Str("groupName", groupName).Msg("found group in FindGroup")

		if strings.EqualFold(group.Name, groupName) {
			h.log.Debug().Str("groupName", groupName).Msg("group name match in FindGroup")

			found = true
			fillGroup = group
		} else {
			h.log.Debug().Str("groupName", groupName).Msg("group name not match in FindGroup")
		}
	}

	return found, fillGroup, nil
}

func (h configHandler) FindPosixAccounts(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	ctx, span := h.tracer.Start(ctx, "handler.configHandler.FindPosixAccounts")
	defer span.End()

	h.log.Debug().Str("hierarchy", hierarchy).Msg("FindPosixAccounts")

	entries := []*ldap.Entry{}

	for _, u := range h.cfg.Users {
		attrs := []*ldap.EntryAttribute{}
		for _, nameAttr := range h.backend.NameFormatAsArray {
			attrs = append(attrs, &ldap.EntryAttribute{Name: nameAttr, Values: []string{u.Name}})
		}

		if len(u.GivenName) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{u.GivenName}})
		}

		if len(u.SN) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "sn", Values: []string{u.SN}})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{h.getGroupName(ctx, u.PrimaryGroup)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{fmt.Sprintf("%d", u.UIDNumber)}})

		if u.Disabled {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"inactive"}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"active"}})
		}

		if len(u.Mail) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{u.Mail}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "userPrincipalName", Values: []string{u.Mail}})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount", "shadowAccount"}})

		if len(u.LoginShell) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{u.LoginShell}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{"/bin/bash"}})
		}

		if len(u.Homedir) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{u.Homedir}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{"/home/" + u.Name}})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{u.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gecos", Values: []string{u.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", u.PrimaryGroup)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "memberOf", Values: h.getGroupDNs(ctx, append(u.OtherGroups, u.PrimaryGroup))})

		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowExpire", Values: []string{"-1"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowFlag", Values: []string{"134538308"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowInactive", Values: []string{"-1"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowLastChange", Values: []string{"11000"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowMax", Values: []string{"99999"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowMin", Values: []string{"-1"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowWarning", Values: []string{"7"}})

		if len(u.SSHKeys) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: h.backend.SSHKeyAttr, Values: u.SSHKeys})
		}

		if len(u.CustomAttrs) > 0 {
			for key, attr := range u.CustomAttrs {
				switch typedattr := attr.(type) {
				case []interface{}:
					var values []string
					for _, v := range typedattr {
						switch typedvalue := v.(type) {
						case string:
							values = append(values, MaybeDecode(typedvalue))
						default:
							values = append(values, MaybeDecode(fmt.Sprintf("%v", typedvalue)))
						}
					}
					attrs = append(attrs, &ldap.EntryAttribute{Name: key, Values: values})
				default:
					h.log.Warn().Str("key", key).Interface("value", attr).Msg("Unable to map custom attribute")
				}
			}
		}

		var dn string

		if hierarchy == "" {
			dn = fmt.Sprintf("%s=%s,%s=%s,%s", h.backend.NameFormatAsArray[0], u.Name, h.backend.GroupFormatAsArray[0], h.getGroupName(ctx, u.PrimaryGroup), h.backend.BaseDN)
		} else {
			dn = fmt.Sprintf("%s=%s,%s=%s,%s,%s", h.backend.NameFormatAsArray[0], u.Name, h.backend.GroupFormatAsArray[0], h.getGroupName(ctx, u.PrimaryGroup), hierarchy, h.backend.BaseDN)
		}
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	return entries, nil
}

func (h configHandler) FindPosixGroups(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	ctx, span := h.tracer.Start(ctx, "handler.configHandler.FindPosixGroups")
	defer span.End()

	h.log.Debug().Str("hierarchy", hierarchy).Msg("FindPosixGroups")

	asGroupOfUniqueNames := hierarchy == "ou=groups"

	entries := []*ldap.Entry{}

	for _, g := range h.cfg.Groups {
		attrs := []*ldap.EntryAttribute{}
		for _, groupAttr := range h.backend.GroupFormatAsArray {
			attrs = append(attrs, &ldap.EntryAttribute{Name: groupAttr, Values: []string{g.Name}})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{g.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", g.GIDNumber)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: h.getGroupMemberDNs(ctx, g.GIDNumber)})
		if asGroupOfUniqueNames {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"groupOfUniqueNames", "top"}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: h.getGroupMemberIDs(ctx, g.GIDNumber)})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup", "top"}})
		}
		dn := fmt.Sprintf("%s=%s,%s,%s", h.backend.GroupFormatAsArray[0], g.Name, hierarchy, h.backend.BaseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	return entries, nil
}

// Close does not actually close anything, because the config data is kept in memory
func (h configHandler) Close(boundDn string, conn net.Conn) error {
	_, span := h.tracer.Start(context.Background(), "handler.configHandler.Close")
	defer span.End()

	h.log.Debug().Str("boundDn", boundDn).Msg("Close")

	stats.Frontend.Add("closes", 1)
	return nil
}

func (h configHandler) getGroupMemberDNs(ctx context.Context, gid int) []string {
	ctx, span := h.tracer.Start(ctx, "handler.configHandler.getGroupMemberDNs")
	defer span.End()

	h.log.Debug().Int("gid", gid).Msg("getGroupMemberDNs")

	var insertOuUsers string
	if h.cfg.Behaviors.LegacyVersion > 0 && h.cfg.Behaviors.LegacyVersion <= 20100 {
		insertOuUsers = ""
	} else {
		insertOuUsers = ",ou=users"
	}
	members := make(map[string]bool)

	// Pre-compute format strings to avoid repeated allocations
	nameFormat := h.backend.NameFormatAsArray[0] + "="
	groupFormat := h.backend.GroupFormatAsArray[0] + "="
	baseDN := h.backend.BaseDN

	for _, u := range h.cfg.Users {
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

	for _, g := range h.cfg.Groups {
		if gid == g.GIDNumber {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid != gid {
					includegroupmembers := h.getGroupMemberDNs(ctx, includegroupid)

					for _, includegroupmember := range includegroupmembers {
						members[includegroupmember] = true
					}
				}
			}
		}
	}

	// Pre-allocate result slice
	m := make([]string, 0, len(members))
	for k := range members {
		m = append(m, k)
	}

	sort.Strings(m)

	return m
}

func (h configHandler) getGroupMemberIDs(ctx context.Context, gid int) []string {
	ctx, span := h.tracer.Start(ctx, "handler.configHandler.getGroupMemberIDs")
	defer span.End()

	h.log.Debug().Int("gid", gid).Msg("getGroupMemberIDs")

	members := make(map[string]bool)
	for _, u := range h.cfg.Users {
		if u.PrimaryGroup == gid {
			members[u.Name] = true
		} else {
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					members[u.Name] = true
				}
			}
		}
	}

	for _, g := range h.cfg.Groups {
		if gid == g.GIDNumber {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid {
					h.log.Warn().Int("groupid", includegroupid).Msg("Ignoring myself as included group")
				} else {
					includegroupmemberids := h.getGroupMemberIDs(ctx, includegroupid)

					for _, includegroupmemberid := range includegroupmemberids {
						members[includegroupmemberid] = true
					}
				}
			}
		}
	}

	m := []string{}
	for k := range members {
		m = append(m, k)
	}

	sort.Strings(m)

	return m
}

// Converts an array of GUIDs into an array of DNs
func (h configHandler) getGroupDNs(ctx context.Context, gids []int) []string {
	ctx, span := h.tracer.Start(ctx, "handler.configHandler.getGroupDNs")
	defer span.End()

	h.log.Debug().Ints("gids", gids).Msg("getGroupDNs")

	groups := make(map[string]bool)
	for _, gid := range gids {
		for _, g := range h.cfg.Groups {
			if g.GIDNumber == gid {
				dn := fmt.Sprintf("%s=%s,ou=groups,%s", h.backend.GroupFormatAsArray[0], g.Name, h.backend.BaseDN)
				groups[dn] = true
			}

			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid && g.GIDNumber != gid {
					includegroupdns := h.getGroupDNs(ctx, []int{g.GIDNumber})

					for _, includegroupdn := range includegroupdns {
						groups[includegroupdn] = true
					}
				}
			}
		}
	}

	g := []string{}
	for k := range groups {
		g = append(g, k)
	}

	sort.Strings(g)

	return g
}

func (h configHandler) getGroupName(ctx context.Context, gid int) string {
	_, span := h.tracer.Start(ctx, "handler.configHandler.getGroupName")
	defer span.End()

	h.log.Debug().Int("gid", gid).Msg("getGroupName")

	for _, g := range h.cfg.Groups {
		if g.GIDNumber == gid {
			return g.Name
		}
	}
	return ""
}
