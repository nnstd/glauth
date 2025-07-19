package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cespare/xxhash"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"

	"github.com/glauth/ldap"
	"github.com/nnstd/glauth/v2/internal/monitoring"
	"github.com/nnstd/glauth/v2/pkg/config"
	"github.com/nnstd/glauth/v2/pkg/stats"
	"github.com/pquerna/otp/totp"
)

// global matcher
var ldapattributematcher = regexp.MustCompile(`(?i)(?P<attribute>[a-zA-Z0-9]+)\s*=\s*(?P<value>.*)`)

type ldapHandler struct {
	backend     config.Backend
	handlers    HandlerWrapper
	doPing      chan bool
	log         *zerolog.Logger
	sessions    sync.Map // for sessions - using sync.Map for better concurrency
	servers     []ldapBackend
	serversLock sync.RWMutex // for servers - using RWMutex for read-heavy operations
	helper      Handler
	attm        *regexp.Regexp

	monitor monitoring.MonitorInterface
	tracer  trace.Tracer

	// Cache for server status JSON to avoid repeated marshaling
	serverStatusCache struct {
		json     string
		lastHash uint64
		mu       sync.RWMutex
	}

	// Connection pool for reusing LDAP connections
	connPool struct {
		connections map[string]chan *ldap.Conn
		mu          sync.RWMutex
		maxPoolSize int
	}
}

type ldapSession struct {
	id   string
	c    net.Conn
	ldap *ldap.Conn
}

type ldapBackendStatus int

const (
	Down ldapBackendStatus = iota
	Up
)

type ldapBackend struct {
	Scheme   string
	Hostname string
	Port     int
	Status   ldapBackendStatus
	Ping     time.Duration
}

func NewLdapHandler(opts ...Option) Handler {
	options := newOptions(opts...)

	handler := ldapHandler{ // set non-zero-value defaults here
		backend:  options.Backend,
		handlers: options.Handlers,
		doPing:   make(chan bool),
		log:      options.Logger,
		helper:   options.Helper,
		attm:     ldapattributematcher,
		monitor:  options.Monitor,
		tracer:   options.Tracer,
	}

	// Initialize connection pool
	handler.connPool.connections = make(map[string]chan *ldap.Conn)
	handler.connPool.maxPoolSize = 10 // Maximum connections per server

	// parse LDAP URLs
	for _, ldapurl := range handler.backend.Servers {
		l, err := parseURL(ldapurl)
		if err != nil {
			handler.log.Error().Err(err).Msg("could not parse url")
			os.Exit(1)
		}
		handler.servers = append(handler.servers, l)

		// Initialize connection pool for this server
		var serverKey strings.Builder
		serverKey.WriteString(l.Hostname)
		serverKey.WriteString(":")
		serverKey.WriteString(strconv.Itoa(l.Port))
		handler.connPool.connections[serverKey.String()] = make(chan *ldap.Conn, handler.connPool.maxPoolSize)
	}

	// test server connectivity before listening, then keep it updated
	handler.monitorServers()

	return &handler
}

func (h *ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	ctx, span := h.tracer.Start(context.Background(), "handler.ldapHandler.Bind")
	defer span.End()

	start := time.Now()
	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "bind", "status": strconv.FormatInt(int64(result), 10)},
			time.Since(start).Seconds(),
		)
	}()

	h.log.Debug().Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("Bind request")

	//	if h.helper != nil {
	lowerBindDN := strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.backend.BaseDN)
	parts := strings.Split(strings.TrimSuffix(lowerBindDN, baseDN), ",")
	userName := strings.TrimPrefix(parts[0], h.backend.NameFormatAsArray[0]+"=")

	validotp := false

	// Find the user
	// We are going to go through all backends and ask
	// until we find our user or die of boredom.
	user := config.User{}
	found := false

	for i, handler := range h.handlers.Handlers {
		found, user, _ = handler.FindUser(ctx, userName, false)
		if found {
			break
		}
		if i >= *h.handlers.Count {
			break
		}
	}

	if !found {
		validotp = true
	} else {
		if len(user.OTPSecret) == 0 {
			validotp = true
		} else {
			if len(bindSimplePw) > 6 {
				otp := bindSimplePw[len(bindSimplePw)-6:]
				bindSimplePw = bindSimplePw[:len(bindSimplePw)-6]
				validotp = totp.Validate(otp, user.OTPSecret)
			}
		}
	}

	if !validotp {
		h.log.Debug().Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("Bind Error: invalid OTP token")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	stats.Frontend.Add("bind_reqs", 1)
	s, err := h.getSession(conn)
	if err != nil {
		stats.Frontend.Add("bind_ldapSession_errors", 1)
		h.log.Debug().Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Err(err).Msg("could not get session")
		return ldap.LDAPResultOperationsError, err
	}

	if err := s.ldap.Bind(bindDN, bindSimplePw); err != nil {
		stats.Frontend.Add("bind_errors", 1)
		h.log.Debug().Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("invalid creds")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	stats.Frontend.Add("bind_successes", 1)
	h.log.Debug().Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("bind success")
	return ldap.LDAPResultSuccess, nil
}

func (h *ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	ctx, span := h.tracer.Start(context.Background(), "handler.ldapHandler.Search")
	defer span.End()

	start := time.Now()
	defer func() {
		status := strconv.FormatInt(int64(result.ResultCode), 10)

		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "search", "status": status},
			time.Since(start).Seconds(),
		)
	}()

	wantAttributes := true
	wantTypesOnly := false

	h.log.Debug().Str("binddn", boundDN).Str("src", conn.RemoteAddr().String()).Str("filter", searchReq.Filter).Msg("Search request")

	// "1.1" has special meaning: it does what an empty attribute list would do
	// if it didn't already mean "return all attributes"
	if len(searchReq.Attributes) == 1 && searchReq.Attributes[0] == "1.1" {
		wantAttributes = false
		searchReq.Attributes = searchReq.Attributes[:0]
	}

	// TypesOnly cannot be true: if it were, glauth would not be able to
	// match the returned values against the query
	if searchReq.TypesOnly {
		wantTypesOnly = true
		searchReq.TypesOnly = false
	}

	stats.Frontend.Add("search_reqs", 1)
	s, err := h.getSession(conn)
	if err != nil {
		stats.Frontend.Add("search_ldapSession_errors", 1)
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, nil
	}
	/*
	   delete_idx := -1
	   pagingSize := uint32(0)
	   for idx, control := range searchReq.Controls {
	       if control.GetControlType() == ldap.ControlTypePaging {
	           fmt.Println(control.GetControlType())
	           pagingSize = control.(*ldap.ControlPaging).PagingSize
	           delete_idx = idx
	       }
	   }
	   if delete_idx >= 0 {
	       searchReq.Controls = append(searchReq.Controls[:delete_idx], searchReq.Controls[delete_idx+1:]...)
	   }
	*/
	search := ldap.NewSearchRequest(
		searchReq.BaseDN,
		searchReq.Scope,
		searchReq.DerefAliases,
		searchReq.SizeLimit,
		searchReq.TimeLimit,
		searchReq.TypesOnly,
		searchReq.Filter,
		searchReq.Attributes,
		searchReq.Controls,
	)

	h.log.Debug().Interface("request", search).Msg("Search request to backend")
	/*
			var sr *ldap.SearchResult
			if pagingSize > 0 {
			    fmt.Printf("Searching with page size == %d\n", pagingSize)
		        sr, err = s.ldap.SearchWithPaging(search, pagingSize)
		    } else {
		        sr, err = s.ldap.Search(search)
		    }
	*/
	sr, err := s.ldap.Search(search)
	h.log.Debug().Interface("result", sr).Msg("Backend Search result")

	if !wantAttributes {
		h.log.Debug().Str("type", "No attributes").Msg("AP: Search Info")
		for _, entry := range sr.Entries {
			entry.Attributes = entry.Attributes[:0]
		}
	}

	if wantTypesOnly {
		h.log.Debug().Str("type", "Types only").Msg("AP: Search Info")
		for _, entry := range sr.Entries {
			for _, attribute := range entry.Attributes {
				attribute.Values = attribute.Values[:0]
			}
		}
	}

	// WART used to debug when testing special cases against
	// glauth acting as a backend, where it may have
	// the same workaround thus hiding the issue
	/*
		for _, entry := range sr.Entries {
			for _, attribute := range entry.Attributes {
				if attribute.Name == "objectclass" {
					attribute.Name = "bogus"
				}
			}
		}
	*/

	// If our original attribute is not present, either because:
	// 1-This is a root query
	// 2-We were asked not to return attributes
	// 3-We were asked not to return values
	// then we re-insert the correct values in there.
	if searchReq.Scope == 0 && searchReq.BaseDN == "" {
		h.log.Debug().Str("type", "Root search detected").Msg("AP: Search Info")
	}

	filters := h.buildReqAttributesList(ctx, searchReq.Filter, []string{})

	for _, filter := range filters {
		attbits := h.attm.FindStringSubmatch(filter)
		for _, entry := range sr.Entries {
			foundattname := false

			for _, attribute := range entry.Attributes {
				if strings.EqualFold(attribute.Name, attbits[1]) {
					foundattname = true
					if len(attbits[2]) == 0 {
						attribute.Values = []string{attbits[2]}
					}
					break
				}
			}

			if !foundattname {
				entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: attbits[1], Values: []string{attbits[2]}})
			}
		}
	}

	ssr := ldap.ServerSearchResult{
		Entries:    sr.Entries,
		Referrals:  sr.Referrals,
		Controls:   sr.Controls,
		ResultCode: ldap.LDAPResultSuccess,
	}
	h.log.Debug().Interface("result", ssr).Msg("Frontend Search result")
	if err != nil {
		e := err.(*ldap.Error)
		h.log.Debug().Err(err).Msg("search Err")
		stats.Frontend.Add("search_errors", 1)
		stats.Frontend.Add("search_failures", 1)
		ssr.ResultCode = ldap.LDAPResultCode(e.ResultCode)
		return ssr, err
	}
	stats.Frontend.Add("search_successes", 1)
	h.log.Debug().Str("filter", search.Filter).Int("numentries", len(ssr.Entries)).Msg("AP: Search OK")
	return ssr, nil
}

func (h *ldapHandler) buildReqAttributesList(ctx context.Context, filter string, filters []string) []string {
	ctx, span := h.tracer.Start(ctx, "handler.ldapHandler.buildReqAttributesList")
	defer span.End()

	maxp := len(filter)
	start := -1
	descended := false

	for p, c := range filter {
		switch c {
		case '(':
			if p+1 < maxp {
				start = p + 1
			}
		case ')':
			if start > -1 {
				descended = true
				filters = h.buildReqAttributesList(ctx, filter[start:p], filters)
			}
			start = -1
		}
	}

	if !descended {
		filters = append(filters, filter)
	}

	return filters
}

// Add is not yet supported for the ldap backend
func (h *ldapHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "handler.ldapHandler.Add")
	defer span.End()

	start := time.Now()
	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "add", "status": strconv.FormatInt(int64(result), 10)},
			time.Since(start).Seconds(),
		)
	}()
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not yet supported for the ldap backend
func (h *ldapHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "handler.ldapHandler.Modify")
	defer span.End()

	start := time.Now()

	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "modify", "status": strconv.FormatInt(int64(result), 10)},
			time.Since(start).Seconds(),
		)
	}()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not yet supported for the ldap backend
func (h *ldapHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "handler.ldapHandler.Delete")
	defer span.End()

	start := time.Now()

	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "delete", "status": strconv.FormatInt(int64(result), 10)},
			time.Since(start).Seconds(),
		)
	}()

	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h *ldapHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (found bool, user config.User, err error) {
	_, span := h.tracer.Start(ctx, "handler.ldapHandler.FindUser")
	defer span.End()
	return false, config.User{}, nil
}

func (h *ldapHandler) FindGroup(ctx context.Context, groupName string) (found bool, group config.Group, err error) {
	_, span := h.tracer.Start(ctx, "handler.ldapHandler.FindGroup")
	defer span.End()

	return false, config.Group{}, nil
}

func (h *ldapHandler) Close(boundDn string, conn net.Conn) error {
	id := connID(conn)

	// Get the session to retrieve the LDAP connection
	if sessionValue, ok := h.sessions.Load(id); ok {
		if session, ok := sessionValue.(ldapSession); ok {
			// Get the server info to return connection to the right pool
			server, err := h.getBestServer()
			if err == nil {
				// Return connection to pool instead of closing it
				h.returnConnectionToPool(server, session.ldap)
			} else {
				// If we can't determine the server, close the connection
				session.ldap.Close()
			}
		}
	}

	conn.Close() // close connection to the server when then client is closed
	h.sessions.Delete(id)
	stats.Frontend.Add("closes", 1)
	stats.Backend.Add("closes", 1)
	return nil
}

// monitorServers tests server connectivity before listening, then keeps it updated
func (h *ldapHandler) monitorServers() {
	err := h.ping()
	if err != nil {
		h.log.Error().Err(err).Msg("could not ping server")
		os.Exit(1)
		// TODO return error
	}
	go func() {
		for {
			select {
			case <-h.doPing:
				h.log.Warn().Msg("doPing requested due to server failure")
				err = h.ping()
				if err != nil {
					h.log.Error().Err(err).Msg("could not ping server")
					os.Exit(1)
					// TODO return error
				}
			case <-time.NewTimer(60 * time.Second).C:
				h.log.Warn().Msg("doPing after timeout")
				err = h.ping()
				if err != nil {
					h.log.Error().Err(err).Msg("could not ping server")
					os.Exit(1)
					// TODO return error
				}
			}
		}
	}()
}

func (h *ldapHandler) getSession(conn net.Conn) (ldapSession, error) {
	id := connID(conn)

	// Try to get existing session
	if sessionValue, ok := h.sessions.Load(id); ok {
		if session, ok := sessionValue.(ldapSession); ok {
			return session, nil
		}
	}

	// Get best server
	server, err := h.getBestServer()
	if err != nil {
		return ldapSession{}, err
	}

	// Try to get connection from pool first
	l, err := h.getConnectionFromPool(server)
	if err != nil {
		select {
		case h.doPing <- true: // non-blocking send
		default:
		}
		return ldapSession{}, err
	}

	s := ldapSession{id: id, c: conn, ldap: l}
	h.sessions.Store(s.id, s)
	return s, nil
}

func (h *ldapHandler) ping() error {
	healthy := false

	for k, s := range h.servers {
		var l *ldap.Conn
		var err error
		start := time.Now()

		// Try to get connection from pool first
		l, err = h.getConnectionFromPool(s)

		elapsed := time.Since(start)
		h.serversLock.Lock()

		if err != nil || l == nil {
			h.log.Error().Str("hostname", s.Hostname).Int("port", s.Port).Err(err).Msg("server ping failed")
			h.servers[k].Ping = 0
			h.servers[k].Status = Down
		} else {
			healthy = true
			h.servers[k].Ping = elapsed
			h.servers[k].Status = Up
			// Return the connection to the pool instead of closing it
			h.returnConnectionToPool(s, l)
		}

		h.serversLock.Unlock()
	}

	h.log.Debug().Interface("servers", h.servers).Msg("Server health")

	// Use cached server status instead of marshaling every time
	serverStatusJSON := h.getCachedServerStatus()
	stats.Backend.Set("servers", stats.Stringer(serverStatusJSON))

	if !healthy {
		return fmt.Errorf("no healthy servers")
	}

	return nil
}

func (h *ldapHandler) getBestServer() (ldapBackend, error) {
	favorite := ldapBackend{}
	forever, err := time.ParseDuration("30m")
	if err != nil {
		return ldapBackend{}, err
	}

	h.serversLock.RLock()
	bestping := forever
	for _, s := range h.servers {
		if s.Status == Up && s.Ping < bestping {
			favorite = s
			bestping = s.Ping
		}
	}
	h.serversLock.RUnlock()

	if bestping == forever {
		return ldapBackend{}, fmt.Errorf("no healthy servers found")
	}

	h.log.Debug().Interface("favorite", favorite).Msg("Best server")
	return favorite, nil
}

// helper functions
func connID(conn net.Conn) string {
	key := conn.LocalAddr().String() + conn.RemoteAddr().String()
	return strconv.FormatUint(xxhash.Sum64String(key), 16)
}

// createConnection creates a new LDAP connection to the specified server
func (h *ldapHandler) createConnection(server ldapBackend) (*ldap.Conn, error) {
	var dest strings.Builder
	dest.WriteString(server.Hostname)
	dest.WriteString(":")
	dest.WriteString(strconv.Itoa(server.Port))

	switch server.Scheme {
	case "ldaps":
		tlsCfg := &tls.Config{}
		if h.backend.Insecure {
			tlsCfg.InsecureSkipVerify = true
		}
		return ldap.DialTLS("tcp", dest.String(), tlsCfg)
	case "ldap":
		return ldap.Dial("tcp", dest.String())
	default:
		return nil, fmt.Errorf("unsupported LDAP scheme: %s", server.Scheme)
	}
}

// getConnectionFromPool tries to get a connection from the pool, creates a new one if pool is empty
func (h *ldapHandler) getConnectionFromPool(server ldapBackend) (*ldap.Conn, error) {
	var serverKey strings.Builder
	serverKey.WriteString(server.Hostname)
	serverKey.WriteString(":")
	serverKey.WriteString(strconv.Itoa(server.Port))

	h.connPool.mu.RLock()
	pool, exists := h.connPool.connections[serverKey.String()]
	h.connPool.mu.RUnlock()

	if !exists {
		// Pool doesn't exist for this server, create new connection
		return h.createConnection(server)
	}

	// Try to get connection from pool
	select {
	case conn := <-pool:
		// Check if connection is still valid
		if conn != nil {
			// For now, assume the connection is valid if it's not nil
			// In a production environment, you might want to add a more sophisticated
			// health check here, but be careful not to add too much overhead
			return conn, nil
		}
	default:
		// Pool is empty, create new connection
	}

	// Create new connection
	return h.createConnection(server)
}

// returnConnectionToPool returns a connection to the pool if there's space
func (h *ldapHandler) returnConnectionToPool(server ldapBackend, conn *ldap.Conn) {
	if conn == nil {
		return
	}

	var serverKey strings.Builder
	serverKey.WriteString(server.Hostname)
	serverKey.WriteString(":")
	serverKey.WriteString(strconv.Itoa(server.Port))

	h.connPool.mu.RLock()
	pool, exists := h.connPool.connections[serverKey.String()]
	h.connPool.mu.RUnlock()

	if !exists {
		// Pool doesn't exist, close connection
		conn.Close()
		return
	}

	// Try to return connection to pool
	select {
	case pool <- conn:
		// Successfully returned to pool
		h.log.Debug().Str("server", serverKey.String()).Msg("Connection returned to pool")
	default:
		// Pool is full, close connection
		conn.Close()
		h.log.Debug().Str("server", serverKey.String()).Msg("Pool full, connection closed")
	}
}

// cleanupConnectionPool closes all connections in the pool
func (h *ldapHandler) cleanupConnectionPool() {
	h.connPool.mu.Lock()
	defer h.connPool.mu.Unlock()

	for serverKey, pool := range h.connPool.connections {
		closeCount := 0
		for {
			select {
			case conn := <-pool:
				if conn != nil {
					conn.Close()
					closeCount++
				}
			default:
				// Pool is empty
				goto nextPool
			}
		}
	nextPool:
		h.log.Info().Str("server", serverKey).Int("connections_closed", closeCount).Msg("Cleaned up connection pool")
	}
}

// computeServerHash computes a fast hash of server status for change detection
func (h *ldapHandler) computeServerHash() uint64 {
	h.serversLock.RLock()
	defer h.serversLock.RUnlock()

	hash := xxhash.New()
	for _, server := range h.servers {
		fmt.Fprintf(hash, "%s:%d:%d:%d", server.Hostname, server.Port, server.Status, server.Ping)
	}
	return hash.Sum64()
}

// getCachedServerStatus returns cached JSON or computes and caches new JSON
func (h *ldapHandler) getCachedServerStatus() string {
	currentHash := h.computeServerHash()

	h.serverStatusCache.mu.RLock()
	if h.serverStatusCache.lastHash == currentHash && h.serverStatusCache.json != "" {
		json := h.serverStatusCache.json
		h.serverStatusCache.mu.RUnlock()
		return json
	}
	h.serverStatusCache.mu.RUnlock()

	// Need to recompute JSON
	h.serverStatusCache.mu.Lock()
	defer h.serverStatusCache.mu.Unlock()

	// Double-check after acquiring write lock
	if h.serverStatusCache.lastHash == currentHash && h.serverStatusCache.json != "" {
		return h.serverStatusCache.json
	}

	// Compute new JSON
	h.serversLock.RLock()
	b, err := json.Marshal(h.servers)
	h.serversLock.RUnlock()

	if err != nil {
		h.log.Error().Err(err).Msg("error encoding server status")
		return "[]"
	}

	jsonStr := string(b)
	h.serverStatusCache.json = jsonStr
	h.serverStatusCache.lastHash = currentHash

	return jsonStr
}

func parseURL(ldapurl string) (ldapBackend, error) {
	u, err := url.Parse(ldapurl)
	if err != nil {
		return ldapBackend{}, err
	}
	var port int

	switch u.Scheme {
	case "ldaps":
		port = 636
	case "ldap":
		port = 389
	default:
		return ldapBackend{}, fmt.Errorf("unknown LDAP scheme: %s", u.Scheme)
	}

	parts := strings.Split(u.Host, ":")
	hostname := parts[0]

	if len(parts) > 1 {
		port, err = strconv.Atoi(parts[1])
		if err != nil {
			return ldapBackend{}, err
		}
	}

	return ldapBackend{Scheme: u.Scheme, Hostname: hostname, Port: port}, nil
}
