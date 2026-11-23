package ingress

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudflare/cloudflared/config"
)

func TestParseAccessControl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     *config.AccessControlConfig
		want    *AccessControl
		wantErr string
	}{
		{
			name: "not configured",
		},
		{
			name: "empty config defaults to deny",
			raw:  &config.AccessControlConfig{},
			want: &AccessControl{
				Default: AccessActionDeny,
				Rules:   []AccessControlRule{},
			},
		},
		{
			name: "parses rules and normalizes methods",
			raw: &config.AccessControlConfig{
				Default: "ALLOW",
				Rules: []config.AccessControlRule{
					{
						Path:    "^/public",
						Methods: []string{"get", "HEAD", "GET"},
						Action:  "Allow",
					},
					{
						Path:   "^/admin",
						Action: "DENY",
					},
				},
			},
			want: &AccessControl{
				Default: AccessActionAllow,
				Rules: []AccessControlRule{
					{
						Path:    MustParsePath(t, "^/public"),
						Methods: []string{"GET", "HEAD"},
						Action:  AccessActionAllow,
					},
					{
						Path:   MustParsePath(t, "^/admin"),
						Action: AccessActionDeny,
					},
				},
			},
		},
		{
			name: "wildcard method matches every method",
			raw: &config.AccessControlConfig{
				Rules: []config.AccessControlRule{
					{Methods: []string{"*"}, Action: "allow"},
				},
			},
			want: &AccessControl{
				Default: AccessActionDeny,
				Rules: []AccessControlRule{
					{Action: AccessActionAllow},
				},
			},
		},
		{
			name: "invalid default action",
			raw: &config.AccessControlConfig{
				Default: "maybe",
			},
			wantErr: "invalid default action",
		},
		{
			name: "invalid rule action",
			raw: &config.AccessControlConfig{
				Rules: []config.AccessControlRule{
					{Action: "maybe"},
				},
			},
			wantErr: "rule #1 has an invalid action",
		},
		{
			name: "invalid path regex",
			raw: &config.AccessControlConfig{
				Rules: []config.AccessControlRule{
					{Path: "["},
				},
			},
			wantErr: "rule #1 has an invalid path regex",
		},
		{
			name: "invalid method",
			raw: &config.AccessControlConfig{
				Rules: []config.AccessControlRule{
					{Methods: []string{"GET POST"}},
				},
			},
			wantErr: "rule #1 has an invalid method list",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseAccessControl(test.raw)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestRuleCheckAccess(t *testing.T) {
	t.Parallel()

	control, err := parseAccessControl(&config.AccessControlConfig{
		Default: "deny",
		Rules: []config.AccessControlRule{
			{
				Path:    `^/api/public$`,
				Methods: []string{"GET", "HEAD"},
				Action:  "allow",
			},
			{
				Path:    `^/health$`,
				Methods: []string{"GET"},
				Action:  "allow",
			},
			{
				Path:   `^/blocked$`,
				Action: "deny",
			},
		},
	})
	require.NoError(t, err)
	defaultAllowControl, err := parseAccessControl(&config.AccessControlConfig{
		Default: "allow",
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		rule        Rule
		method      string
		url         string
		wantAllowed bool
		wantRule    int
	}{
		{
			name:        "no ACL preserves existing behavior",
			rule:        Rule{},
			method:      "DELETE",
			url:         "https://app.example.com/anything",
			wantAllowed: true,
			wantRule:    0,
		},
		{
			name:        "matching path and method is allowed",
			rule:        Rule{AccessControl: control},
			method:      "get",
			url:         "https://app.example.com/api/public",
			wantAllowed: true,
			wantRule:    0,
		},
		{
			name:        "matching path but wrong method is denied by default",
			rule:        Rule{AccessControl: control},
			method:      "POST",
			url:         "https://app.example.com/api/public",
			wantAllowed: false,
			wantRule:    -1,
		},
		{
			name:        "explicit deny rule is selected",
			rule:        Rule{AccessControl: control},
			method:      "POST",
			url:         "https://app.example.com/blocked",
			wantAllowed: false,
			wantRule:    2,
		},
		{
			name:        "default allow permits a path without an explicit rule",
			rule:        Rule{AccessControl: defaultAllowControl},
			method:      "DELETE",
			url:         "https://app.example.com/anything",
			wantAllowed: true,
			wantRule:    -1,
		},
		{
			name:        "dot segments are canonicalized before evaluation",
			rule:        Rule{AccessControl: control},
			method:      "GET",
			url:         "https://app.example.com/api/public/../private",
			wantAllowed: false,
			wantRule:    -1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			requestURL, err := url.Parse(test.url)
			require.NoError(t, err)
			decision := test.rule.CheckAccess(test.method, requestURL)
			assert.Equal(t, test.wantAllowed, decision.Allowed)
			assert.Equal(t, test.wantRule, decision.RuleIndex)
		})
	}
}

func TestParseIngressAccessControlFromYAML(t *testing.T) {
	t.Parallel()

	ing, err := ParseIngress(MustReadIngress(`
ingress:
  - hostname: app.example.com
    service: http_status:204
    accessControl:
      default: deny
      rules:
        - path: ^/public$
          methods: [GET, HEAD]
          action: allow
  - service: http_status:404
`))
	require.NoError(t, err)
	require.Len(t, ing.Rules, 2)

	decision := ing.Rules[0].CheckAccess(http.MethodGet, &url.URL{Path: "/public"})
	assert.True(t, decision.Configured)
	assert.True(t, decision.Allowed)

	decision = ing.Rules[0].CheckAccess(http.MethodPost, &url.URL{Path: "/public"})
	assert.True(t, decision.Configured)
	assert.False(t, decision.Allowed)
}

func TestAccessControlTenIngressRulesConcurrent(t *testing.T) {
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
					{
						Path:    fmt.Sprintf(`^/admin-%d$`, i),
						Methods: []string{"GET"},
						Action:  "allow",
					},
				},
			},
		})
	}
	rawIngress = append(rawIngress, config.UnvalidatedIngressRule{Service: "http_status:404"})

	ing, err := ParseIngress(&config.Configuration{Ingress: rawIngress})
	require.NoError(t, err)

	type testCase struct {
		name        string
		ruleIndex   int
		method      string
		path        string
		wantAllowed bool
	}
	tests := make([]testCase, 0, ruleCount*4)
	for i := 0; i < ruleCount; i++ {
		tests = append(tests,
			testCase{name: fmt.Sprintf("rule %d allows public GET", i), ruleIndex: i, method: "GET", path: fmt.Sprintf("/public-%d", i), wantAllowed: true},
			testCase{name: fmt.Sprintf("rule %d denies public POST", i), ruleIndex: i, method: "POST", path: fmt.Sprintf("/public-%d", i), wantAllowed: false},
			testCase{name: fmt.Sprintf("rule %d allows admin GET", i), ruleIndex: i, method: "GET", path: fmt.Sprintf("/admin-%d", i), wantAllowed: true},
			testCase{name: fmt.Sprintf("rule %d denies admin DELETE", i), ruleIndex: i, method: "DELETE", path: fmt.Sprintf("/admin-%d", i), wantAllowed: false},
		)
	}

	type result struct {
		testCase
		actualRuleIndex int
		decision        AccessDecision
	}
	results := make(chan result, len(tests))
	var wg sync.WaitGroup
	for _, test := range tests {
		test := test
		wg.Add(1)
		go func() {
			defer wg.Done()
			requestURL := &url.URL{Path: test.path}
			rule, ruleIndex := ing.FindMatchingRule(fmt.Sprintf("app-%d.example.com", test.ruleIndex), requestURL)
			results <- result{
				testCase:        test,
				actualRuleIndex: ruleIndex,
				decision:        rule.CheckAccess(test.method, requestURL),
			}
		}()
	}
	wg.Wait()
	close(results)

	for result := range results {
		assert.Equal(t, result.ruleIndex, result.actualRuleIndex, result.name)
		assert.Equal(t, result.wantAllowed, result.decision.Allowed, result.name)
		assert.True(t, result.decision.Configured, result.name)
	}
}
