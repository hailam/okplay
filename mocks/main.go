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
		if err := http.ListenAndServe(":4001", router); err != nil {
			log.Error("Failed to start mock auth server: %v", err)
		} else {
			log.Info("Mock auth server listening on :4001")
		}
	}()
}

// handleIntrospect handles OAuth2 token introspection
func handleIntrospect(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	slog.Info("Received introspection request", "token", token)

	// Check Authorization header if token not in form
	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	var response IntrospectionResponse

	oneHourInFuture := time.Now().Add(time.Hour).Unix()

	switch token {
	case "ory_at_valid-machine-token":
		response = IntrospectionResponse{
			Active:   true,
			Aud:      []string{"machines"},
			ClientID: "test-machine-client",
			Expires:  oneHourInFuture,
		}
	case "ory_at_valid-psp-token":
		response = IntrospectionResponse{
			Active:   true,
			Aud:      []string{"psp"},
			ClientID: "test-psp-client",
			Expires:  oneHourInFuture,
		}
	case "ory_at_valid-machine-psp-token":
		response = IntrospectionResponse{
			Active:   true,
			Aud:      []string{"machines", "psp"},
			ClientID: "test-psp-client",
			Expires:  oneHourInFuture,
		}
	default:
		response = IntrospectionResponse{Active: false}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleWhoami handles session checks
func handleWhoami(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// Check for session cookie
	cookie, err := r.Cookie("ory_session")
	validCookie := err == nil && cookie.Value == "valid-session-cookie"

	// Check for bearer token
	authHeader := r.Header.Get("Authorization")
	validBearer := authHeader == "Bearer ory_st_valid-user-token"

	if validCookie || validBearer {
		response := SessionResponse{
			Active: true,
			Identity: map[string]interface{}{
				"id": "user-123",
				"traits": map[string]interface{}{
					"email": "user@example.com",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Return 401 Unauthorized
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
}

// StartUpstreamService starts the mock upstream service
func StartUpstreamService() {
	router := httprouter.New()

	// Generic handler for all paths
	router.Handle("GET", "/wallet/*path", captureHeaders)
	router.Handle("POST", "/wallet/*path", captureHeaders)
	router.Handle("PUT", "/wallet/*path", captureHeaders)
	router.Handle("DELETE", "/wallet/*path", captureHeaders)
	router.Handle("PATCH", "/wallet/*path", captureHeaders)

	router.Handle("GET", "/switch/*path", captureHeaders)
	router.Handle("POST", "/switch/*path", captureHeaders)
	router.Handle("PUT", "/switch/*path", captureHeaders)
	router.Handle("DELETE", "/switch/*path", captureHeaders)
	router.Handle("PATCH", "/switch/*path", captureHeaders)

	router.Handle("GET", "/shared/*path", captureHeaders)
	router.Handle("POST", "/shared/*path", captureHeaders)
	router.Handle("PUT", "/shared/*path", captureHeaders)
	router.Handle("DELETE", "/shared/*path", captureHeaders)
	router.Handle("PATCH", "/shared/*path", captureHeaders)

	go func() {
		if err := http.ListenAndServe(":4002", router); err != nil {
			slog.Error("Failed to start upstream service", "error", err)
			log.Warn("Failed to start upstream service: %v", err)
		} else {
			log.Info("Upstream service started successfully")
		}
	}()
}

// captureHeaders captures the headers sent by Oathkeeper
func captureHeaders(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	// Create a unique key for this request
	key := fmt.Sprintf("%s:%s", r.Method, r.URL.Path)

	// Store headers for testing
	capturedMutex.Lock()
	capturedHeaders[key] = r.Header.Clone()
	capturedMutex.Unlock()

	// Log received headers for debugging
	log.Info("Received request to %s %s", r.Method, r.URL.Path)
	log.Info("X-Auth-Source: %s", r.Header.Get("X-Auth-Source"))
	log.Info("X-Auth-Details: %s", r.Header.Get("X-Auth-Details"))

	// Return success response
	response := map[string]interface{}{
		"status": "success",
		"path":   r.URL.Path,
		"method": r.Method,
		"headers": map[string]string{
			"X-Auth-Source":  r.Header.Get("X-Auth-Source"),
			"X-Auth-Details": r.Header.Get("X-Auth-Details"),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetCapturedHeaders returns captured headers for a given method and path (for testing)
func GetCapturedHeaders(method, path string) http.Header {
	capturedMutex.RLock()
	defer capturedMutex.RUnlock()

	key := fmt.Sprintf("%s:%s", method, path)
	return capturedHeaders[key]
}

// ClearCapturedHeaders clears all captured headers (for testing)
func ClearCapturedHeaders() {
	capturedMutex.Lock()
	defer capturedMutex.Unlock()

	capturedHeaders = make(map[string]http.Header)
}
