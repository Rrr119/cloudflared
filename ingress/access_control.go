package ingress

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/cloudflare/cloudflared/config"
)

const (
	// AccessActionAllow permits a request that matches a policy rule.
	AccessActionAllow = "allow"
	// AccessActionDeny rejects a request that matches a policy rule.
	AccessActionDeny = "deny"

	defaultAccessAction = AccessActionDeny
)

var httpMethodRegexp = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

// AccessControl is the parsed form of config.AccessControlConfig.
type AccessControl struct {
	Default string              `json:"default,omitempty"`
	Rules   []AccessControlRule `json:"rules"`
}

// AccessControlRule is a parsed access control rule. Path is nil when the
// rule applies to every path.
type AccessControlRule struct {
	Path    *Regexp  `json:"path,omitempty"`
	Methods []string `json:"methods,omitempty"`
	Action  string   `json:"action"`
}

// AccessDecision describes the result of evaluating an ingress rule's ACL.
type AccessDecision struct {
	// Configured is false when the ingress rule has no ACL. Allowed is always
	// true in that case so callers can treat it as a normal ingress request.
	Configured bool
	Allowed    bool
	Action     string
	// RuleIndex is the index of the matching ACL rule, or -1 for the default
	// action.
	RuleIndex int
	Reason    string
}

func parseAccessControl(raw *config.AccessControlConfig) (*AccessControl, error) {
	if raw == nil {
		return nil, nil
	}

	defaultAction, err := normalizeAccessAction(raw.Default, true)
	if err != nil {
		return nil, fmt.Errorf("invalid default action: %w", err)
	}

	accessControl := &AccessControl{
		Default: defaultAction,
		Rules:   make([]AccessControlRule, len(raw.Rules)),
	}
	for i, rawRule := range raw.Rules {
		var path *Regexp
		if rawRule.Path != "" {
			compiled, err := regexp.Compile(rawRule.Path)
			if err != nil {
				return nil, fmt.Errorf("rule #%d has an invalid path regex: %w", i+1, err)
			}
			path = &Regexp{Regexp: compiled}
		}

		methods, err := normalizeMethods(rawRule.Methods)
		if err != nil {
			return nil, fmt.Errorf("rule #%d has an invalid method list: %w", i+1, err)
		}

		action, err := normalizeAccessAction(rawRule.Action, false)
		if err != nil {
			return nil, fmt.Errorf("rule #%d has an invalid action: %w", i+1, err)
		}

		accessControl.Rules[i] = AccessControlRule{
			Path:    path,
			Methods: methods,
			Action:  action,
		}
	}

	return accessControl, nil
}

func normalizeAccessAction(action string, allowEmpty bool) (string, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" && allowEmpty {
		return defaultAccessAction, nil
	}

	switch action {
	case AccessActionAllow, AccessActionDeny:
		return action, nil
	default:
		return "", fmt.Errorf("expected %q or %q, got %q", AccessActionAllow, AccessActionDeny, action)
	}
}

func normalizeMethods(methods []string) ([]string, error) {
	if len(methods) == 0 {
		return nil, nil
	}

	normalized := make([]string, 0, len(methods))
	seen := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "*" {
			return nil, nil
		}
		if !httpMethodRegexp.MatchString(method) {
			return nil, fmt.Errorf("invalid HTTP method %q", method)
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		normalized = append(normalized, method)
	}
	return normalized, nil
}

// CheckAccess evaluates the ingress rule's ACL for a request path and method.
// Rules are evaluated in order and the first match wins. The path is
// canonicalized using the same normalization used for ingress selection so
// dot-segment and encoded-separator variants cannot bypass a policy.
func (r *Rule) CheckAccess(method string, requestURL *url.URL) AccessDecision {
	if r == nil || r.AccessControl == nil {
		return AccessDecision{Allowed: true}
	}

	requestPath := "/"
	if requestURL != nil {
		requestPath = canonicalPathForMatching(requestURL.EscapedPath())
	}
	method = strings.ToUpper(strings.TrimSpace(method))

	for i, rule := range r.AccessControl.Rules {
		if !rule.matches(method, requestPath) {
			continue
		}
		return AccessDecision{
			Configured: true,
			Allowed:    rule.Action == AccessActionAllow,
			Action:     rule.Action,
			RuleIndex:  i,
			Reason:     fmt.Sprintf("matched access control rule #%d", i+1),
		}
	}

	return AccessDecision{
		Configured: true,
		Allowed:    r.AccessControl.Default == AccessActionAllow,
		Action:     r.AccessControl.Default,
		RuleIndex:  -1,
		Reason:     "no access control rule matched; applied default action",
	}
}

func (r AccessControlRule) matches(method, requestPath string) bool {
	if r.Path != nil && r.Path.Regexp != nil && !r.Path.MatchString(requestPath) {
		return false
	}
	if len(r.Methods) == 0 {
		return true
	}
	for _, allowedMethod := range r.Methods {
		if allowedMethod == method {
			return true
		}
	}
	return false
}
