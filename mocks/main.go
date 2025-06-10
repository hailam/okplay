package mocks

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/julienschmidt/httprouter"
	log "unknwon.dev/clog/v2"
)

// Global storage for captured headers (for testing)
var (
	capturedHeaders = make(map[string]http.Header)
	capturedMutex   sync.RWMutex
)

// IntrospectionResponse represents the OAuth2 introspection response
type IntrospectionResponse struct {
	Active   bool     `json:"active"`
	Aud      []string `json:"aud,omitempty"`
	Scope    string   `json:"scope,omitempty"`
	ClientID string   `json:"client_id,omitempty"`
	Expires  int64    `json:"exp,omitempty"`
}

// SessionResponse represents the session/whoami response
type SessionResponse struct {
	Active   bool                   `json:"active"`
	Identity map[string]interface{} `json:"identity"`
}

// StartMockAuthServer starts the mock authentication server
func StartMockAuthServer() {
	router := httprouter.New()

	// OAuth2 introspection endpoint
	router.POST("/introspect", handleIntrospect)

	// Session whoami endpoint
	router.GET("/sessions/whoami", handleWhoami)

	go func() {
		log.Info("Mock auth server listening on :4001")
		if err := http.ListenAndServe(":4001", router); err != nil {
			log.Error("Failed to start mock auth server: %v", err)
		}
	}()
}

// handleIntrospect handles OAuth2 token introspection
func handleIntrospect(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	slog.Info("Received introspection request", "token", token)

	var response IntrospectionResponse
	oneHourInFuture := time.Now().Add(time.Hour).Unix()

	switch token {
	case "ory_at_wallet-machine-token":
		response = IntrospectionResponse{Active: true, Aud: []string{"wallet"}, Scope: "machines", ClientID: "wallet-machine", Expires: oneHourInFuture}
	case "ory_at_switch-machine-token":
		response = IntrospectionResponse{Active: true, Aud: []string{"switch"}, Scope: "machines", ClientID: "switch-machine", Expires: oneHourInFuture}
	case "ory_at_switch-psp-token":
		response = IntrospectionResponse{Active: true, Aud: []string{"switch"}, Scope: "psp", ClientID: "psp-client", Expires: oneHourInFuture}
	case "ory_at_shared-machine-token":
		response = IntrospectionResponse{Active: true, Aud: []string{"shared"}, Scope: "machines", ClientID: "shared-machine", Expires: oneHourInFuture}
	case "ory_at_backoffice-machine-token":
		response = IntrospectionResponse{Active: true, Aud: []string{"backoffice"}, Scope: "machines", ClientID: "backoffice-machine", Expires: oneHourInFuture}
	case "ory_at_user-token-for-wallet":
		response = IntrospectionResponse{Active: true, Aud: []string{"wallet"}, Scope: "read write", ClientID: "user-client", Expires: oneHourInFuture}
	default:
		response = IntrospectionResponse{Active: false}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleWhoami handles session checks
func handleWhoami(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var sessionID, identityID, schemaID string

	// Check for session cookie
	if cookie, err := r.Cookie("ory_session_cookie"); err == nil {
		sessionID = cookie.Value
	}

	// Check for bearer token
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ory_st_") {
		sessionID = strings.TrimPrefix(authHeader, "Bearer ")
	}

	switch sessionID {
	case "ory_st_valid-session-normal-user", "valid-session-normal-user":
		identityID = "user-normal-123"
		schemaID = "normal_users"
	case "ory_st_valid-session-backoffice-user", "valid-session-backoffice-user":
		identityID = "user-backoffice-456"
		schemaID = "backoffice_users"
	default:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	response := SessionResponse{
		Active: true,
		Identity: map[string]interface{}{
			"id":        identityID,
			"schema_id": schemaID,
			"traits": map[string]interface{}{
				"email": fmt.Sprintf("%s@example.com", identityID),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// StartUpstreamService starts the mock upstream service
func StartUpstreamService() {
	router := httprouter.New()

	handler := func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		key := fmt.Sprintf("%s:%s", r.Method, r.URL.Path)
		capturedMutex.Lock()
		capturedHeaders[key] = r.Header.Clone()
		capturedMutex.Unlock()

		log.Info("Upstream received request to %s", r.URL.Path)
		log.Info("X-Auth-Source: %s", r.Header.Get("X-Auth-Source"))
		log.Info("X-Auth-Details: %s", r.Header.Get("X-Auth-Details"))

		response := map[string]interface{}{
			"status":  "success",
			"path":    r.URL.Path,
			"headers": r.Header,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}

	router.Handle("GET", "/*path", handler)
	router.Handle("POST", "/*path", handler)
	router.Handle("PUT", "/*path", handler)
	router.Handle("DELETE", "/*path", handler)
	router.Handle("PATCH", "/*path", handler)

	go func() {
		log.Info("Upstream service listening on :4002")
		if err := http.ListenAndServe(":4002", router); err != nil {
			slog.Error("Failed to start upstream service", "error", err)
		}
	}()
}
