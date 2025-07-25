package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"

	"github.com/glauth/ldap"
	"github.com/nnstd/glauth/v2/internal/monitoring"
	"github.com/nnstd/glauth/v2/pkg/config"
	"github.com/nnstd/glauth/v2/pkg/stats"
	msgraph "github.com/yaegashi/msgraph.go/v1.0"
)

type ownCloudSession struct {
	log         *zerolog.Logger
	client      *http.Client
	user        string
	password    string
	endpoint    string
	useGraphAPI bool
}
type ownCloudHandler struct {
	backend  config.Backend
	log      *zerolog.Logger
	client   *http.Client
	sessions sync.Map // for sessions - using sync.Map for better concurrency

	monitor monitoring.MonitorInterface
	tracer  trace.Tracer
}

func NewOwnCloudHandler(opts ...Option) Handler {
	options := newOptions(opts...)

	return &ownCloudHandler{
		backend: options.Backend,
		log:     options.Logger,
		client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: options.Backend.Insecure,
				},
			},
		},
		monitor: options.Monitor,
		tracer:  options.Tracer,
	}
}

func (h *ownCloudHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	start := time.Now()
	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "bind", "status": fmt.Sprintf("%v", result)},
			time.Since(start).Seconds(),
		)
	}()

	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.backend.BaseDN)

	h.log.Debug().Str("binddn", bindDN).Str("basedn", h.backend.BaseDN).Str("src", conn.RemoteAddr().String()).Msg("Bind request")

	stats.Frontend.Add("bind_reqs", 1)

	// parse the bindDN - ensure that the bindDN ends with the BaseDN
	if !strings.HasSuffix(bindDN, baseDN) {
		h.log.Warn().Str("binddn", bindDN).Str("basedn", h.backend.BaseDN).Msg("BindDN not part of our BaseDN")
		return ldap.LDAPResultInvalidCredentials, nil
	}
	parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
	if len(parts) > 2 {
		h.log.Warn().Str("binddn", bindDN).Int("numparts", len(parts)).Msg("BindDN should have only one or two parts")
		return ldap.LDAPResultInvalidCredentials, nil
	}
	userName := strings.TrimPrefix(parts[0], "cn=")

	// try to login
	if !h.login(userName, bindSimplePw) {
		h.log.Warn().Str("username", userName).Str("basedn", h.backend.BaseDN).Msg("Login failed")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// TODO reuse HTTP connection
	id := connID(conn)
	s := ownCloudSession{
		log:         h.log,
		user:        userName,
		password:    bindSimplePw,
		endpoint:    h.backend.Servers[0],
		useGraphAPI: h.backend.UseGraphAPI,
		client:      h.client,
	}
	h.sessions.Store(id, s)

	stats.Frontend.Add("bind_successes", 1)
	h.log.Debug().Str("binddn", bindDN).Str("basedn", h.backend.BaseDN).Str("src", conn.RemoteAddr().String()).Msg("Bind success")
	return ldap.LDAPResultSuccess, nil
}

func (h *ownCloudHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	start := time.Now()
	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "search", "status": fmt.Sprintf("%v", result.ResultCode)},
			time.Since(start).Seconds(),
		)
	}()

	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.backend.BaseDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)
	h.log.Debug().Str("binddn", bindDN).Str("basedn", baseDN).Str("src", conn.RemoteAddr().String()).Str("filter", searchReq.Filter).Msg("Search request")
	stats.Frontend.Add("search_reqs", 1)

	// validate the user is authenticated and has appropriate access
	if len(bindDN) < 1 {
		stats.Frontend.Add("search_failures", 1)
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: Anonymous BindDN not allowed %s", bindDN)
	}
	if !strings.HasSuffix(bindDN, baseDN) {
		stats.Frontend.Add("search_failures", 1)
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: BindDN %s not in our BaseDN %s", bindDN, h.backend.BaseDN)
	}
	if !strings.HasSuffix(searchBaseDN, h.backend.BaseDN) {
		stats.Frontend.Add("search_failures", 1)
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: search BaseDN %s is not in our BaseDN %s", searchBaseDN, h.backend.BaseDN)
	}
	// return all users in the config file - the LDAP library will filter results for us
	// Pre-allocate entries slice with estimated capacity
	entries := make([]*ldap.Entry, 0, 100) // Estimate 100 entries
	filterEntity, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		stats.Frontend.Add("search_failures", 1)
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: error parsing filter: %s", searchReq.Filter)
	}
	id := connID(conn)
	sessionValue, ok := h.sessions.Load(id)
	if !ok {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("session not found")
	}
	session, ok := sessionValue.(ownCloudSession)
	if !ok {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("invalid session type")
	}

	switch filterEntity {
	default:
		stats.Frontend.Add("search_failures", 1)
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: unhandled filter type: %s [%s]", filterEntity, searchReq.Filter)
	case "posixgroup":
		groups, err := session.getGroups()
		if err != nil {
			stats.Frontend.Add("search_failures", 1)
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("search error: error getting groups")
		}
		for _, g := range groups {
			// Pre-allocate attributes slice with estimated capacity
			attrs := make([]*ldap.EntryAttribute, 0, 10) // Estimate 10 attributes per group

			for _, groupAttr := range h.backend.GroupFormatAsArray {
				attrs = append(attrs, &ldap.EntryAttribute{Name: groupAttr, Values: []string{*g.ID}})
			}

			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s from ownCloud", *g.ID)}})
			//			attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", g.GIDNumber)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup"}})

			if g.Members != nil {
				members := make([]string, len(g.Members))
				for i, v := range g.Members {
					members[i] = *v.ID
				}

				attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: members})
			}

			dn := fmt.Sprintf("%s=%s,ou=groups,%s", h.backend.GroupFormatAsArray[0], *g.ID, h.backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	case "posixaccount", "":
		userName := ""
		if searchBaseDN != strings.ToLower(h.backend.BaseDN) {
			parts := strings.Split(strings.TrimSuffix(searchBaseDN, baseDN), ",")
			if len(parts) >= 1 {
				userName = strings.TrimPrefix(parts[0], "cn=")
			}
		}

		users, err := session.getUsers(userName)

		if err != nil {
			h.log.Debug().Str("username", userName).Err(err).Msg("Could not get user")
			stats.Frontend.Add("search_failures", 1)
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("search error: error getting users")
		}

		for _, u := range users {
			// Pre-allocate attributes slice with estimated capacity
			attrs := make([]*ldap.EntryAttribute, 0, 10) // Estimate 10 attributes per user

			for _, nameAttr := range h.backend.NameFormatAsArray {
				attrs = append(attrs, &ldap.EntryAttribute{Name: nameAttr, Values: []string{*u.ID}})
			}

			if u.DisplayName != nil {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{*u.DisplayName}})
			}

			if u.Mail != nil {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{*u.Mail}})
			}

			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount"}})

			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s from ownCloud", *u.ID)}})

			dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.backend.NameFormatAsArray[0], *u.ID, h.backend.GroupFormatAsArray[0], "users", h.backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	}

	stats.Frontend.Add("search_successes", 1)
	h.log.Debug().Str("filter", searchReq.Filter).Msg("AP: Search OK")
	return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
}

// Add is not yet supported for the owncloud backend
func (h *ownCloudHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	start := time.Now()
	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "add", "status": fmt.Sprintf("%v", result)},
			time.Since(start).Seconds(),
		)
	}()
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not yet supported for the owncloud backend
func (h *ownCloudHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	start := time.Now()
	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "modify", "status": fmt.Sprintf("%v", result)},
			time.Since(start).Seconds(),
		)
	}()
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not yet supported for the owncloud backend
func (h *ownCloudHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "handler.configHandler.Delete")
	defer span.End()

	start := time.Now()
	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "delete", "status": fmt.Sprintf("%v", result)},
			time.Since(start).Seconds(),
		)
	}()
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// FindUser with the given username. Called by the ldap backend to authenticate the bind. Optional
func (h *ownCloudHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (found bool, user config.User, err error) {
	_, span := h.tracer.Start(ctx, "handler.ownCloudHandler.FindUser")
	defer span.End()

	return false, config.User{}, nil
}

func (h *ownCloudHandler) FindGroup(ctx context.Context, groupName string) (found bool, group config.Group, err error) {
	_, span := h.tracer.Start(ctx, "handler.ownCloudHandler.FindGroup")
	defer span.End()

	return false, config.Group{}, nil
}

func (h *ownCloudHandler) Close(boundDN string, conn net.Conn) error {
	conn.Close() // close connection to the server when then client is closed
	h.sessions.Delete(connID(conn))
	stats.Frontend.Add("closes", 1)
	stats.Backend.Add("closes", 1)
	return nil
}

func (h *ownCloudHandler) login(name, pw string) bool {
	var req *http.Request
	if h.backend.UseGraphAPI {
		// TODO oc10 graphapi app should implement /me
		req, _ = http.NewRequest("GET", h.backend.Servers[0]+"/users/"+name, nil)
	} else {
		// use provisioning api
		meURL := fmt.Sprintf("%s/ocs/v2.php/cloud/user?format=json", h.backend.Servers[0])
		req, _ = http.NewRequest("GET", meURL, nil)
	}
	req.SetBasicAuth(name, pw)
	resp, err := h.client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		h.log.Error().Err(err).Int("status", resp.StatusCode).Msg("failed login")
		return false
	}
	defer resp.Body.Close()
	return true
}

type OCSGroupsResponse struct {
	Ocs struct {
		Meta struct {
			Message    interface{} `json:"message"`
			Statuscode int         `json:"statuscode"`
			Status     string      `json:"status"`
		} `json:"meta"`
		Data struct {
			Groups []string `json:"groups"`
		} `json:"data"`
	} `json:"ocs"`
}

func (s ownCloudSession) getGroups() ([]msgraph.Group, error) {
	if s.useGraphAPI {
		ctx := context.Background()
		req := s.NewClient().Groups().Request()
		req.Expand("members")
		return req.Get(ctx)
	}
	groupsUrl := fmt.Sprintf("%s/ocs/v2.php/cloud/groups?format=json", s.endpoint)

	req, _ := http.NewRequest("GET", groupsUrl, nil)
	req.SetBasicAuth(s.user, s.password)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var f OCSGroupsResponse
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}

	ret := make([]msgraph.Group, len(f.Ocs.Data.Groups))
	for i := range f.Ocs.Data.Groups {
		ret[i] = msgraph.Group{DirectoryObject: msgraph.DirectoryObject{Entity: msgraph.Entity{ID: &f.Ocs.Data.Groups[i]}}}
	}

	return ret, nil
}

type OCSUsersResponse struct {
	Ocs struct {
		Data struct {
			Users []string `json:"users"`
		} `json:"data"`
		Meta struct {
			Statuscode int         `json:"statuscode"`
			Message    interface{} `json:"message"`
			Status     string      `json:"status"`
		} `json:"meta"`
	} `json:"ocs"`
}

// NewClient returns GraphService request builder with default base URL
func (s ownCloudSession) NewClient() *msgraph.GraphServiceRequestBuilder {
	httpClient := &http.Client{
		Transport: s,
	}
	g := msgraph.NewClient(httpClient)
	g.SetURL(s.endpoint)
	return g
}

func (s ownCloudSession) RoundTrip(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(s.user, s.password)
	return s.client.Transport.RoundTrip(req)
}

func (s ownCloudSession) getUsers(userName string) ([]msgraph.User, error) {
	if s.useGraphAPI {
		s.log.Debug().Msg("using graph api")
		ctx := context.Background()
		req := s.NewClient().Users()
		if len(userName) > 0 {
			s.log.Debug().Msg("fetching single user")
			u, err := req.ID(userName).Request().Get(ctx)
			if err != nil {
				return nil, err
			}
			return []msgraph.User{*u}, nil
		}
		s.log.Debug().Msg("fetching all users")
		return req.Request().Get(ctx)
	}
	s.log.Debug().Msg("using provisioning api")
	usersUrl := fmt.Sprintf("%s/ocs/v2.php/cloud/users?format=json", s.endpoint)

	req, _ := http.NewRequest("GET", usersUrl, nil)
	req.SetBasicAuth(s.user, s.password)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var f OCSUsersResponse
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}

	ret := make([]msgraph.User, len(f.Ocs.Data.Users))
	for i := range f.Ocs.Data.Users {
		ret[i] = msgraph.User{
			DirectoryObject: msgraph.DirectoryObject{
				Entity: msgraph.Entity{ID: &f.Ocs.Data.Users[i]},
			},
		}
	}

	return ret, nil
}

func (s ownCloudSession) redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	s.log.Debug().Str("username", s.user).Msg("Setting user and password")
	req.SetBasicAuth(s.user, s.password)
	return nil
}
