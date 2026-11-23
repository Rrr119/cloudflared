package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudflare/cloudflared/config"
	cfdflow "github.com/cloudflare/cloudflared/flow"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/tracing"
)

func TestAccessControlTenIngressRulesConcurrentProxy(t *testing.T) {
	t.Parallel()

	const ruleCount = 10
	rawIngress := make([]config.UnvalidatedIngressRule, 0, ruleCount+1)
	for i := 0; i < ruleCount; i++ {
		rawIngress = append(rawIngress, config.UnvalidatedIngressRule{
			Hostname: fmt.Sprintf("app-%d.example.com", i),
			Service:  "http_status:204",
			AccessControl: &config.AccessControlConfig{
				Default: "deny",
				Rules: []config.AccessControlRule{
					{
						Path:    fmt.Sprintf(`^/public-%d$`, i),
						Methods: []string{"GET", "HEAD"},
						Action:  "allow",
					},
				},
			},
		})
	}
	rawIngress = append(rawIngress, config.UnvalidatedIngressRule{Service: "http_status:404"})

	ing, err := ingress.ParseIngress(&config.Configuration{Ingress: rawIngress})
	require.NoError(t, err)

	log := zerolog.Nop()
	originProxy := NewOriginProxy(ing, nil, nil, cfdflow.NewLimiter(0), &log)

	type testCase struct {
		name       string
		ruleIndex  int
		method     string
		wantStatus int
	}
	tests := make([]testCase, 0, ruleCount*3)
	for i := 0; i < ruleCount; i++ {
		tests = append(tests,
			testCase{name: fmt.Sprintf("rule %d allows GET", i), ruleIndex: i, method: http.MethodGet, wantStatus: http.StatusNoContent},
			testCase{name: fmt.Sprintf("rule %d allows HEAD", i), ruleIndex: i, method: http.MethodHead, wantStatus: http.StatusNoContent},
			testCase{name: fmt.Sprintf("rule %d denies POST", i), ruleIndex: i, method: http.MethodPost, wantStatus: http.StatusForbidden},
		)
	}

	type result struct {
		testCase
		err    error
		status int
	}
	results := make(chan result, len(tests))
	var wg sync.WaitGroup
	for _, test := range tests {
		test := test
		wg.Add(1)
		go func() {
			defer wg.Done()
			request, err := http.NewRequest(
				test.method,
				fmt.Sprintf("https://app-%d.example.com/public-%d", test.ruleIndex, test.ruleIndex),
				nil,
			)
			if err != nil {
				results <- result{testCase: test, err: err}
				return
			}
			responseWriter := newMockHTTPRespWriter()
			err = originProxy.ProxyHTTP(
				responseWriter,
				tracing.NewTracedHTTPRequest(request, 0, &log),
				false,
			)
			results <- result{testCase: test, err: err, status: responseWriter.Code}
		}()
	}
	wg.Wait()
	close(results)

	for result := range results {
		require.NoError(t, result.err, result.name)
		assert.Equal(t, result.wantStatus, result.status, result.name)
	}
}

func TestAccessControlAuditLog(t *testing.T) {
	t.Parallel()

	var logOutput bytes.Buffer
	log := zerolog.New(&logOutput)
	ing, err := ingress.ParseIngress(&config.Configuration{
		Ingress: []config.UnvalidatedIngressRule{
			{
				Hostname: "app.example.com",
				Service:  "http_status:204",
				AccessControl: &config.AccessControlConfig{
					Default: "deny",
					Rules: []config.AccessControlRule{
						{
							Path:    `^/public$`,
							Methods: []string{"GET"},
							Action:  "allow",
						},
					},
				},
			},
			{Service: "http_status:404"},
		},
	})
	require.NoError(t, err)

	originProxy := NewOriginProxy(ing, nil, nil, cfdflow.NewLimiter(0), &log)
	requests := []struct {
		method     string
		wantStatus int
	}{
		{method: http.MethodGet, wantStatus: http.StatusNoContent},
		{method: http.MethodPost, wantStatus: http.StatusForbidden},
	}
	for _, requestSpec := range requests {
		request, err := http.NewRequest(requestSpec.method, "https://app.example.com/public", nil)
		require.NoError(t, err)
		request.Header.Set("Cf-Connecting-IP", "192.0.2.10")
		request.Header.Set("Cf-Access-Authenticated-User-Email", "user@example.com")

		responseWriter := newMockHTTPRespWriter()
		err = originProxy.ProxyHTTP(
			responseWriter,
			tracing.NewTracedHTTPRequest(request, 3, &log),
			false,
		)
		require.NoError(t, err)
		assert.Equal(t, requestSpec.wantStatus, responseWriter.Code)
	}

	auditEvents := parseAuditEvents(t, logOutput.Bytes())
	require.Len(t, auditEvents, 2)

	sessionID := auditEvents[0]["sessionID"]
	require.NotEmpty(t, sessionID)
	assert.Equal(t, sessionID, auditEvents[1]["sessionID"])

	assert.Equal(t, "GET", auditEvents[0]["method"])
	assert.Equal(t, "allow", auditEvents[0]["accessAction"])
	assert.Equal(t, true, auditEvents[0]["accessAllowed"])
	assert.InDelta(t, float64(http.StatusNoContent), auditEvents[0]["statusCode"], 0)
	assert.Equal(t, "user@example.com", auditEvents[0]["principal"])
	assert.Equal(t, "192.0.2.10", auditEvents[0]["clientIP"])

	assert.Equal(t, "POST", auditEvents[1]["method"])
	assert.Equal(t, "deny", auditEvents[1]["accessAction"])
	assert.Equal(t, false, auditEvents[1]["accessAllowed"])
	assert.InDelta(t, float64(http.StatusForbidden), auditEvents[1]["statusCode"], 0)
}

func TestAccessAuditWriterPreservesFlusher(t *testing.T) {
	t.Parallel()

	responseWriter := newMockHTTPRespWriter()
	auditWriter := &accessAuditWriter{ResponseWriter: responseWriter}
	flusher, ok := any(auditWriter).(http.Flusher)
	require.True(t, ok)

	flusher.Flush()
	assert.True(t, responseWriter.Flushed)
}

func parseAuditEvents(t *testing.T, logOutput []byte) []map[string]any {
	t.Helper()

	var events []map[string]any
	for _, line := range bytes.Split(logOutput, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event map[string]any
		require.NoError(t, json.Unmarshal(line, &event))
		if event["auditEvent"] == "http_access" {
			events = append(events, event)
		}
	}
	return events
}
