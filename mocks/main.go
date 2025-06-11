// Package mocks provides mock servers for testing OAuth2, session, upstream, and remote authz flows.
package mocks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/julienschmidt/httprouter"
	log "unknwon.dev/clog/v2"
)

// capturedHeaders stores headers captured by the mock servers for assertions.
var (
	capturedHeaders = make(map[string]http.Header)
	headersMu       sync.RWMutex
)

// IntrospectionResponse represents the OAuth2 token introspection response.
type IntrospectionResponse struct {
	Active   bool     `json:"active"`
	Aud      []string `json:"aud,omitempty"`
	Scope    string   `json:"scope,omitempty"`
	ClientID string   `json:"client_id,omitempty"`
	Expires  int64    `json:"exp,omitempty"`
}

// SessionResponse represents the session / whoami response.
type SessionResponse struct {
	Active   bool                   `json:"active"`
	Identity map[string]interface{} `json:"identity"`
}

// RequestPayload is the expected payload for remote authz.
type RequestPayload struct {
	Context              *ContextData `json:"context,omitempty"`
	AllowedUserSchemaIDs []string     `json:"allowed_user_schema_ids,omitempty"`
}

// ContextData holds contextual information for authz decisions.
type ContextData struct {
	Subject string     `json:"subject,omitempty"`
	Extra   *ExtraData `json:"extra,omitempty"`
}

// ExtraData holds identity and scope information.
type ExtraData struct {
	Identity *Identity `json:"identity,omitempty"`
	Aud      []string  `json:"aud,omitempty"`
	Scope    string    `json:"scope,omitempty"`
}

// Identity holds the user's schema ID.
type Identity struct {
	SchemaID string `json:"schema_id,omitempty"`
}

// writeJSON sends a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error("writeJSON encode failed: %v", err)
	}
}

// StartMockAuthServer runs the mock auth server on port 4001.
func StartMockAuthServer() {
	router := httprouter.New()
	router.POST("/introspect", handleIntrospect)
	router.GET("/sessions/whoami", handleWhoami)

	go func() {
		log.Info("Mock auth server listening on :4001")
		if err := http.ListenAndServe(":4001", router); err != nil {
			log.Error("mock auth server failed: %v", err)
		}
	}()
}

// handleIntrospect handles the /introspect endpoint.
func handleIntrospect(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form"})
		return
	}
	token := r.FormValue("token")
	log.Info("introspect request received: token=%v", token)

	responses := map[string]IntrospectionResponse{
		"ory_at_wallet-machine-token":     {true, []string{"wallet"}, "machines", "wallet-machine", expiresIn(time.Hour)},
		"ory_at_switch-machine-token":     {true, []string{"switch"}, "machines", "switch-machine", expiresIn(time.Hour)},
		"ory_at_switch-psp-token":         {true, []string{"switch"}, "psp", "psp-client", expiresIn(time.Hour)},
		"ory_at_shared-machine-token":     {true, []string{"shared"}, "machines", "shared-machine", expiresIn(time.Hour)},
		"ory_at_backoffice-machine-token": {true, []string{"backoffice"}, "machines", "backoffice-machine", expiresIn(time.Hour)},
		"ory_at_user-token-for-wallet":    {true, []string{"wallet"}, "read write", "user-client", expiresIn(time.Hour)},
	}

	resp, ok := responses[token]
	if !ok {
		resp = IntrospectionResponse{Active: false}
	}
	writeJSON(w, http.StatusOK, resp)
}

// expiresIn returns a Unix timestamp `d` from now.
func expiresIn(d time.Duration) int64 {
	return time.Now().Add(d).Unix()
}

// handleWhoami handles the /sessions/whoami endpoint.
func handleWhoami(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	sessionID := extractSessionID(r)
	identityID, schemaID, ok := resolveSession(sessionID)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	response := SessionResponse{
		Active: true,
		Identity: map[string]interface{}{
			"id":        identityID,
			"schema_id": schemaID,
			"traits":    map[string]interface{}{"email": fmt.Sprintf("%s@example.com", identityID)},
		},
	}
	writeJSON(w, http.StatusOK, response)
}

// extractSessionID retrieves session ID from cookie or Authorization header.
func extractSessionID(r *http.Request) string {
	if c, err := r.Cookie("ory_session_cookie"); err == nil {
		return c.Value
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ory_st_") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// resolveSession maps a session ID to identity details.
func resolveSession(s string) (string, string, bool) {
	switch s {
	case "ory_st_valid-session-normal-user", "valid-session-normal-user":
		return "user-normal-123", "normal_users", true
	case "ory_st_valid-session-backoffice-user", "valid-session-backoffice-user":
		return "user-backoffice-456", "backoffice_users", true
	default:
		return "", "", false
	}
}

// StartUpstreamService runs the mock upstream service on port 4002.
func StartUpstreamService() {
	router := httprouter.New()
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
		router.Handle(m, "/*path", upstreamHandler)
	}
	go func() {
		log.Info("Upstream service listening on :4002")
		if err := http.ListenAndServe(":4002", router); err != nil {
			log.Error("upstream service failed: %v", err)
		}
	}()
}

// upstreamHandler captures headers and responds with request info.
func upstreamHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	key := fmt.Sprintf("%s:%s", r.Method, r.URL.Path)
	headersMu.Lock()
	capturedHeaders[key] = r.Header.Clone()
	headersMu.Unlock()
	log.Info("upstream request: path=%s X-Auth-Source=%s", r.URL.Path, r.Header.Get("X-Auth-Source"))
	resp := map[string]interface{}{"status": "success", "path": r.URL.Path, "headers": r.Header}
	writeJSON(w, http.StatusOK, resp)
}

// StartMockRemoteAuthZServer runs the mock remote authz server on port 4003.
func StartMockRemoteAuthZServer() {
	router := httprouter.New()
	router.POST("/remote-authz", handleRemoteAuthZ)
	go func() {
		log.Info("Mock remote authz server listening on :4003")
		if err := http.ListenAndServe(":4003", router); err != nil {
			log.Error("remote authz server failed: %v", err)
		}
	}()
}

// handleRemoteAuthZ handles the /remote-authz endpoint.
func handleRemoteAuthZ(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	r.Body.Close()
	log.Info("remote-authz raw body=%s", string(body))

	var rp RequestPayload
	if err := json.Unmarshal(body, &rp); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	log.Info("remote-authz payload: payload=%v", rp)

	userType := determineUserType(rp.Context)
	schemaID := ""
	if rp.Context != nil && rp.Context.Extra != nil && rp.Context.Extra.Identity != nil {
		schemaID = rp.Context.Extra.Identity.SchemaID
	}
	allowed := isAllowed(userType, schemaID, rp.AllowedUserSchemaIDs)

	headersMu.Lock()
	capturedHeaders[r.Method+":"+r.URL.Path] = r.Header.Clone()
	headersMu.Unlock()

	resp := map[string]interface{}{"status": "", "user_type": userType, "allowed": allowed}
	if allowed {
		resp["status"] = "authorized"
	} else {
		resp["status"] = "unauthorized"
		resp["reason"] = "user type not in allowed schemas"
	}
	code := http.StatusOK
	if !allowed {
		code = http.StatusForbidden
	}
	writeJSON(w, code, resp)
}

// determineUserType applies template logic to decide user type.
func determineUserType(ctx *ContextData) string {
	if ctx == nil {
		return "unknown"
	}
	if isNormalUser(ctx) || isBackofficeUser(ctx) {
		return "user"
	}
	if ctx.Extra != nil && len(ctx.Extra.Aud) > 0 {
		if strings.Contains(ctx.Extra.Scope, "machines") {
			return "machines"
		}
		return "user"
	}
	if ctx.Subject == "public" {
		return "public"
	}
	return "unknown"
}

// isNormalUser checks for normal_users schema.
func isNormalUser(ctx *ContextData) bool {
	return ctx.Extra != nil && ctx.Extra.Identity != nil && ctx.Extra.Identity.SchemaID == "normal_users"
}

// isBackofficeUser checks for backoffice_users schema.
func isBackofficeUser(ctx *ContextData) bool {
	return ctx.Extra != nil && ctx.Extra.Identity != nil && ctx.Extra.Identity.SchemaID == "backoffice_users"
}

// isAllowed determines if a request is authorized based on userType and allowed schemas.
func isAllowed(userType, schemaID string, allowed []string) bool {
	switch userType {
	case "user":
		for _, s := range allowed {
			if s == schemaID {
				return true
			}
		}
		return false
	case "machines", "public":
		return true
	default:
		return false
	}
}
