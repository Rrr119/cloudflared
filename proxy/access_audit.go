package proxy

import (
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/ingress"
)

const (
	logFieldAuditEvent    = "auditEvent"
	logFieldAuditSession  = "sessionID"
	logFieldAccessAction  = "accessAction"
	logFieldAccessAllowed = "accessAllowed"
	logFieldPolicyRule    = "policyRule"
	logFieldPolicyReason  = "policyReason"
	logFieldPrincipal     = "principal"
	logFieldClientIP      = "clientIP"
	logFieldStatusCode    = "statusCode"
	logFieldDurationMs    = "durationMs"

	auditEventHTTPAccess = "http_access"
)

// accessAuditWriter records the status sent to the edge so the audit event can
// include the final outcome of an allowed request.
type accessAuditWriter struct {
	connection.ResponseWriter
	status int
}

func (w *accessAuditWriter) Status() int {
	return w.status
}

func (w *accessAuditWriter) WriteRespHeaders(status int, header http.Header) error {
	w.status = status
	return w.ResponseWriter.WriteRespHeaders(status, header)
}

func (w *accessAuditWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *accessAuditWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func (w *accessAuditWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (p *Proxy) logAccessAudit(
	logger *zerolog.Logger,
	req *http.Request,
	connIndex uint8,
	ruleNum int,
	serviceName string,
	decision ingress.AccessDecision,
	statusCode int,
	elapsed time.Duration,
) {
	level := zerolog.InfoLevel
	if !decision.Allowed {
		level = zerolog.WarnLevel
	}

	logger.WithLevel(level).
		Str(logFieldAuditEvent, auditEventHTTPAccess).
		Str(logFieldAuditSession, fmt.Sprintf("%s-%d", p.sessionID, connIndex)).
		Str("host", req.Host).
		Str("method", req.Method).
		Str("path", req.URL.Path).
		Int(logFieldRule, ruleNum).
		Str(logFieldOriginService, serviceName).
		Str(logFieldAccessAction, decision.Action).
		Bool(logFieldAccessAllowed, decision.Allowed).
		Int(logFieldPolicyRule, decision.RuleIndex).
		Str(logFieldPolicyReason, decision.Reason).
		Int(logFieldStatusCode, statusCode).
		Int64(logFieldDurationMs, elapsed.Milliseconds()).
		Str(logFieldPrincipal, requestPrincipal(req)).
		Str(logFieldClientIP, req.Header.Get("Cf-Connecting-IP")).
		Msg("HTTP access audit")
}

func requestPrincipal(req *http.Request) string {
	if principal := req.Header.Get("Cf-Access-Authenticated-User-Email"); principal != "" {
		return principal
	}
	return req.Header.Get("Cf-Access-User-Email")
}
