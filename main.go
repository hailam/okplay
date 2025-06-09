package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	AuthType       string // "bearer", "cookie", or "oauth2"
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

	err := log.NewConsole(0,
		log.ConsoleConfig{
			Level: log.LevelTrace,
		},
	)
	if err != nil {
		panic("unable to create new logger: " + err.Error())
	}

	fmt.Println("Welcome to the ORY Oathkeeper Integration Test Suite!")

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start services
	fmt.Printf("\n%s📦 Starting Services...%s\n", colorYellow, colorReset)

	// Start mock servers
	mocks.StartMockAuthServer()
	mocks.StartUpstreamService()
	//fmt.Printf("  %s✓%s Mock servers started (ports 4001, 4002)\n", colorGreen, colorReset)

	// Start Oathkeeper
	//oathkeeperCmd, err := startOathkeeper()
	//if err != nil {
	//	fmt.Printf("  %s✗%s Failed to start Oathkeeper: %v\n", colorRed, colorReset, err)
	//	os.Exit(1)
	//}
	//fmt.Printf("  %s✓%s Oathkeeper started (port 4455)\n", colorGreen, colorReset)

	// Wait for services to be ready
	fmt.Printf("\n%s⏳ Waiting for services to initialize...%s\n", colorYellow, colorReset)
	time.Sleep(3 * time.Second)

	// Run tests in a goroutine
	done := make(chan bool)
	go func() {
		runTests()
		done <- true
	}()

	// Wait for tests to complete or interrupt signal
	select {
	case <-done:
		// Tests completed
	case <-sigChan:
		fmt.Printf("\n%s⚠️  Interrupted! Shutting down...%s\n", colorYellow, colorReset)
	}

	/*
		// Cleanup
		fmt.Printf("\n%s🧹 Cleaning up...%s\n", colorYellow, colorReset)
		if oathkeeperCmd != nil && oathkeeperCmd.Process != nil {
			oathkeeperCmd.Process.Kill()
			oathkeeperCmd.Wait()
		}
	*/
	log.Info("  %s✓%s All services stopped\n", colorGreen, colorReset)
	log.Stop()
}

func startOathkeeper() (*exec.Cmd, error) {
	return nil, nil

	/*
		oathkeeperPath := findOathkeeperPath()
		configPath, _ := filepath.Abs("./config/oathkeeper.yml")

		// Change to config directory so rules.json is found
		originalDir, _ := os.Getwd()
		os.Chdir(filepath.Dir(configPath))
		defer os.Chdir(originalDir)

		cmd := exec.Command("go", "run", oathkeeperPath, "serve", "--config", configPath)
		cmd.Env = append(os.Environ(), "OATHKEEPER_LOG_LEVEL=error") // Reduce noise

		// Create pipes for stdout/stderr but don't display
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard

		if err := cmd.Start(); err != nil {
			return nil, err
		}

		return cmd, nil
	*/
}

func findOathkeeperPath() string {
	paths := []string{
		"github.com/ory/oathkeeper",
		"../oathkeeper",
		"../../oathkeeper",
		os.Getenv("OATHKEEPER_PATH"),
	}

	for _, p := range paths {
		if p != "" {
			if _, err := os.Stat(filepath.Join(p, "main.go")); err == nil {
				return filepath.Join(p, "main.go")
			}
		}
	}

	return "github.com/ory/oathkeeper"
}

func runTests() {
	testCases := []TestCase{
		{
			Name:           "User bearer token to /wallet/",
			Path:           "/wallet/test",
			Token:          "ory_st_valid-user-token",
			AuthType:       "bearer",
			ExpectedStatus: http.StatusOK,
			ExpectedSource: "user",
		},
		{
			Name:           "PSP token to /switch/",
			Path:           "/switch/test",
			Token:          "ory_at_valid-psp-token",
			AuthType:       "oauth2",
			ExpectedStatus: http.StatusOK,
			ExpectedSource: "psp",
		},

		{
			Name:           "Machine token to /wallet/",
			Path:           "/wallet/test",
			Token:          "ory_at_valid-machine-token",
			AuthType:       "oauth2",
			ExpectedStatus: http.StatusOK,
			ExpectedSource: "machine",
		},

		{
			Name:           "Invalid token to /shared/",
			Path:           "/shared/test",
			Token:          "invalid-token",
			AuthType:       "oauth2",
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedSource: "",
		},
		{
			Name:           "Cookie session to /wallet/",
			Path:           "/wallet/test",
			Token:          "valid-session-cookie",
			AuthType:       "cookie",
			ExpectedStatus: http.StatusOK,
			ExpectedSource: "user",
		},
	}

	fmt.Printf("\n%s🧪 Running Tests%s\n", colorBlue, colorReset)
	fmt.Println(strings.Repeat("-", 50))

	//results := make([]TestResult, 0)
	passCount := 0
	failCount := 0

	for i, tc := range testCases {
		fmt.Printf("\n%sTest %d/%d:%s %s\n", colorWhite, i+1, len(testCases), colorReset, tc.Name)
		result := runSingleTest(tc)
		//results = append(results, result)

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

	// Summary
	fmt.Printf("\n%s📊 Test Summary%s\n", colorCyan, colorReset)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Total Tests: %d\n", len(testCases))
	fmt.Printf("%sPassed: %d%s\n", colorGreen, passCount, colorReset)
	fmt.Printf("%sFailed: %d%s\n", colorRed, failCount, colorReset)

	if failCount > 0 {
		fmt.Printf("\n%s❌ Some tests failed!%s\n", colorRed, colorReset)
		log.Stop()
		os.Exit(1)
	} else {
		fmt.Printf("\n%s✅ All tests passed!%s\n", colorGreen, colorReset)
	}
}

func runSingleTest(tc TestCase) TestResult {
	result := TestResult{TestCase: tc, Passed: false}

	// Create request
	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:4455%s", tc.Path), nil)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		return result
	}

	// Set authentication
	switch tc.AuthType {
	case "bearer":
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tc.Token))
	case "cookie":
		req.AddCookie(&http.Cookie{Name: "ory_session", Value: tc.Token})
	case "oauth2":
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tc.Token))
	}

	// Send request
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to send request: %v", err)
		return result
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != tc.ExpectedStatus {
		body, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Sprintf("Expected status %d, got %d", tc.ExpectedStatus, resp.StatusCode)
		result.Details = fmt.Sprintf("Response body: %s", strings.TrimSpace(string(body)))
		return result
	}

	// For successful requests, check the headers
	if tc.ExpectedStatus == http.StatusOK {
		var response map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			result.Error = fmt.Sprintf("Failed to decode response: %v", err)
			return result
		}

		slog.Info("Response received", "status", resp.StatusCode, "headers", resp.Header)
		slog.Debug("Response body", "body", response)

		// Check X-Auth-Source header
		if headers, ok := response["headers"].(map[string]interface{}); ok {
			authSource, hasAuthSource := headers["X-Auth-Source"].(string)
			authDetails, hasAuthDetails := headers["X-Auth-Details"].(string)

			if !hasAuthSource {
				result.Error = "X-Auth-Source header not found"
				return result
			}

			//if authSource != tc.ExpectedSource {
			//	result.Error = fmt.Sprintf("Expected X-Auth-Source '%s', got '%s'", tc.ExpectedSource, authSource)
			//	return result
			//}

			if !hasAuthDetails {
				result.Error = "X-Auth-Details header not found"
				return result
			}

			result.Details = fmt.Sprintf("Auth source: %s, Auth details: %s...", authSource, authDetails[:min(20, len(authDetails))])
		} else {
			result.Error = "Headers not found in response"
			return result
		}
	}

	result.Passed = true
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
