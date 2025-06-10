package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hailam/okplay/mocks"
	log "unknwon.dev/clog/v2"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

type TestCase struct {
	Name           string
	Path           string
	Token          string
	Cookie         string
	ExpectedStatus int
	ExpectedSource string
}

type TestResult struct {
	TestCase TestCase
	Passed   bool
	Error    string
	Details  string
}

func main() {
	fmt.Printf("%s🚀 ORY Oathkeeper Integration Test Suite%s\n", colorCyan, colorReset)
	fmt.Println(strings.Repeat("=", 50))

	err := log.NewConsole(0, log.ConsoleConfig{Level: log.LevelTrace})
	if err != nil {
		panic("unable to create new logger: " + err.Error())
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start services
	fmt.Printf("\n%s📦 Starting Services...%s\n", colorYellow, colorReset)
	mocks.StartMockAuthServer()
	mocks.StartUpstreamService()

	// oathkeeperCmd, err := startOathkeeper()
	// if err != nil {
	// 	fmt.Printf("  %s✗%s Failed to start Oathkeeper: %v\n", colorRed, colorReset, err)
	// 	os.Exit(1)
	// }

	fmt.Printf("\n%s⏳ Waiting for services to initialize...%s\n", colorYellow, colorReset)
	time.Sleep(3 * time.Second)

	done := make(chan bool)
	go func() {
		runTests()
		done <- true
	}()

	select {
	case <-done:
	case <-sigChan:
		fmt.Printf("\n%s⚠️  Interrupted! Shutting down...%s\n", colorYellow, colorReset)
	}

	fmt.Printf("\n%s🧹 Cleaning up...%s\n", colorYellow, colorReset)
	// if oathkeeperCmd != nil && oathkeeperCmd.Process != nil {
	// 	oathkeeperCmd.Process.Kill()
	// 	oathkeeperCmd.Wait()
	// }
	log.Info("  %s✓%s All services stopped\n", colorGreen, colorReset)
	log.Stop()
}

func startOathkeeper() (*exec.Cmd, error) {
	cmd := exec.Command("oathkeeper", "serve", "--config", "./config/oathkeeper.yml")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start oathkeeper. Is it installed and in your PATH? Error: %w", err)
	}
	return cmd, nil
}

func runTests() {
	testCases := []TestCase{
		// Wallet Namespace
		{Name: "[Wallet] Allow normal user via bearer token", Path: "/wallet/balance", Token: "ory_st_valid-session-normal-user", ExpectedStatus: http.StatusOK, ExpectedSource: "user"},
		{Name: "[Wallet] Allow normal user via cookie", Path: "/wallet/balance", Cookie: "valid-session-normal-user", ExpectedStatus: http.StatusOK, ExpectedSource: "user"},
		{Name: "[Wallet] Allow machine client", Path: "/wallet/system", Token: "ory_at_wallet-machine-token", ExpectedStatus: http.StatusOK, ExpectedSource: "machines"},
		// !!!!! fails because we can't make a decision based on whoami alone since it returns 200 even for backoffice users, either we do this from app's middleware
		// or we go for custom omni authenticator
		{Name: "[Wallet] Deny backoffice user", Path: "/wallet/balance", Cookie: "valid-session-backoffice-user", ExpectedStatus: http.StatusUnauthorized},
		{Name: "[Wallet] Allow public access (no auth)", Path: "/wallet/public/check", ExpectedStatus: http.StatusOK, ExpectedSource: "public"},

		// Backoffice Namespace
		{Name: "[Backoffice] Allow backoffice user via bearer token", Path: "/backoffice/dashboard", Token: "ory_st_valid-session-backoffice-user", ExpectedStatus: http.StatusOK, ExpectedSource: "user"},
		{Name: "[Backoffice] Allow backoffice user via cookie", Path: "/backoffice/dashboard", Cookie: "valid-session-backoffice-user", ExpectedStatus: http.StatusOK, ExpectedSource: "user"},
		{Name: "[Backoffice] Allow machine client", Path: "/backoffice/system", Token: "ory_at_backoffice-machine-token", ExpectedStatus: http.StatusOK, ExpectedSource: "machines"},
		// !!!!! fails because we can't make a decision based on whoami alone since it returns 200 even for normal users, either we do this from app's middleware
		// or we go for custom omni authenticator
		{Name: "[Backoffice] Deny normal user", Path: "/backoffice/dashboard", Cookie: "valid-session-normal-user", ExpectedStatus: http.StatusUnauthorized},

		// Switch Namespace
		{Name: "[Switch] Allow PSP client", Path: "/switch/payment", Token: "ory_at_switch-psp-token", ExpectedStatus: http.StatusOK, ExpectedSource: "psp"},
		{Name: "[Switch] Allow machine client", Path: "/switch/system", Token: "ory_at_switch-machine-token", ExpectedStatus: http.StatusOK, ExpectedSource: "machines"},
		{Name: "[Switch] Deny normal user", Path: "/switch/payment", Cookie: "valid-session-normal-user", ExpectedStatus: http.StatusUnauthorized},

		// Shared Namespace
		{Name: "[Shared] Allow machine client", Path: "/shared/resource", Token: "ory_at_shared-machine-token", ExpectedStatus: http.StatusOK, ExpectedSource: "machines"},
		{Name: "[Shared] Deny PSP client (wrong audience)", Path: "/shared/resource", Token: "ory_at_switch-psp-token", ExpectedStatus: http.StatusForbidden},
		{Name: "[Shared] Deny normal user", Path: "/shared/resource", Cookie: "valid-session-normal-user", ExpectedStatus: http.StatusUnauthorized},

		// General Denial
		{Name: "[General] Deny invalid token", Path: "/wallet/secure", Token: "invalid-token", ExpectedStatus: http.StatusUnauthorized},
	}

	fmt.Printf("\n%s🧪 Running Tests%s\n", colorBlue, colorReset)
	fmt.Println(strings.Repeat("-", 50))

	passCount, failCount := 0, 0
	for i, tc := range testCases {
		fmt.Printf("\n%sTest %d/%d:%s %s\n", colorWhite, i+1, len(testCases), colorReset, tc.Name)
		result := runSingleTest(tc)
		if result.Passed {
			fmt.Printf("  %s✓ PASSED%s\n", colorGreen, colorReset)
			passCount++
		} else {
			fmt.Printf("  %s✗ FAILED%s: %s\n", colorRed, colorReset, result.Error)
			failCount++
		}
		if result.Details != "" {
			fmt.Printf("  %sDetails:%s %s\n", colorPurple, colorReset, result.Details)
		}
	}

	fmt.Printf("\n%s📊 Test Summary%s\n", colorCyan, colorReset)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Total Tests: %d\n", len(testCases))
	fmt.Printf("%sPassed: %d%s\n", colorGreen, passCount, colorReset)
	fmt.Printf("%sFailed: %d%s\n", colorRed, failCount, colorReset)

	if failCount > 0 {
		fmt.Printf("\n%s❌ Some tests failed!%s\n", colorRed, colorReset)
		os.Exit(1)
	} else {
		fmt.Printf("\n%s✅ All tests passed!%s\n", colorGreen, colorReset)
	}
}

func runSingleTest(tc TestCase) TestResult {
	result := TestResult{TestCase: tc}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:4455%s", tc.Path), nil)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		return result
	}

	if tc.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tc.Token))
	}
	if tc.Cookie != "" {
		req.AddCookie(&http.Cookie{Name: "ory_session_cookie", Value: tc.Cookie})
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to send request: %v", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != tc.ExpectedStatus {
		body, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Sprintf("Expected status %d, got %d", tc.ExpectedStatus, resp.StatusCode)
		result.Details = fmt.Sprintf("Response body: %s", strings.TrimSpace(string(body)))
		return result
	}

	if tc.ExpectedSource != "" {
		var responseData map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
			result.Error = fmt.Sprintf("Failed to decode response: %v", err)
			return result
		}

		headers, ok := responseData["headers"].(map[string]interface{})
		if !ok {
			result.Error = "Headers not found in upstream response"
			return result
		}
		authSourceHeader, ok := headers["X-Auth-Source"].([]interface{})
		if !ok || len(authSourceHeader) == 0 {
			result.Error = "X-Auth-Source header not found or empty"
			return result
		}

		authSource := authSourceHeader[0].(string)
		if authSource != tc.ExpectedSource {
			result.Error = fmt.Sprintf("Expected X-Auth-Source '%s', got '%s'", tc.ExpectedSource, authSource)
			return result
		}
	}

	result.Passed = true
	return result
}
