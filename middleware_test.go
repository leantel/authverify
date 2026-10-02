package authverify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serveWithMiddleware(t *testing.T, verifier *Verifier, authorization string) (*httptest.ResponseRecorder, *Claims) {
	t.Helper()
	var seenClaims *Claims
	protected := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenClaims, _ = FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/orders", nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	protected.ServeHTTP(recorder, request)
	return recorder, seenClaims
}

func TestMiddleware_ValidBearerToken_PutsClaimsInContext(t *testing.T) {
	issuer := newTestIssuer(t)
	now := testNow
	recorder, claims := serveWithMiddleware(t, newTestVerifier(t, issuer, &now), "Bearer "+issuer.sign(t, issuer.validClaims(), nil, issuer.privateKey))
	if recorder.Code != http.StatusNoContent || claims == nil || claims.TenantID != "ten_1" {
		t.Fatalf("status %d claims %+v, want 204 and the token's claims", recorder.Code, claims)
	}
}

func TestMiddleware_BadToken_Is401InvalidTokenAndNoStore(t *testing.T) {
	issuer := newTestIssuer(t)
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	for name, authorization := range map[string]string{
		"garbage token": "Bearer not-a-token", "lower-case scheme with garbage": "bearer not-a-token",
	} {
		recorder, claims := serveWithMiddleware(t, verifier, authorization)
		var body map[string]string
		_ = json.Unmarshal(recorder.Body.Bytes(), &body)
		if recorder.Code != http.StatusUnauthorized || recorder.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` ||
			body["error"] != "invalid_token" || recorder.Header().Get("Cache-Control") != "no-store" || claims != nil {
			t.Errorf("%s: status %d headers %v body %v, want 401 invalid_token no-store", name, recorder.Code, recorder.Header(), body)
		}
		if strings.Contains(recorder.Body.String(), "kid") || strings.Contains(recorder.Body.String(), "crypto") {
			t.Errorf("%s: body leaks verification internals: %s", name, recorder.Body.String())
		}
	}
}

func TestMiddleware_NoCredentials_Is401WithBareChallenge(t *testing.T) {
	issuer := newTestIssuer(t)
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	for name, authorization := range map[string]string{
		"missing header": "", "basic scheme": "Basic dXNlcjpwYXNz", "empty bearer": "Bearer ", "scheme only": "Bearer",
	} {
		recorder, claims := serveWithMiddleware(t, verifier, authorization)
		var body map[string]string
		_ = json.Unmarshal(recorder.Body.Bytes(), &body)
		if recorder.Code != http.StatusUnauthorized || recorder.Header().Get("WWW-Authenticate") != "Bearer" || body["error"] != "" || claims != nil {
			t.Errorf("%s: status %d challenge %q body %v, want 401 with a bare Bearer challenge (RFC 6750 §3.1)",
				name, recorder.Code, recorder.Header().Get("WWW-Authenticate"), body)
		}
	}
}

func TestMiddleware_LowerCaseBearerScheme_IsAccepted(t *testing.T) {
	issuer := newTestIssuer(t)
	now := testNow
	recorder, claims := serveWithMiddleware(t, newTestVerifier(t, issuer, &now), "bearer "+issuer.sign(t, issuer.validClaims(), nil, issuer.privateKey))
	if recorder.Code != http.StatusNoContent || claims == nil {
		t.Fatalf("status %d, want 204 (the auth scheme is case-insensitive)", recorder.Code)
	}
}

func TestRequireScope_ChecksTheScopeClaim(t *testing.T) {
	issuer := newTestIssuer(t)
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	token := "Bearer " + issuer.sign(t, issuer.validClaims(), nil, issuer.privateKey)
	for scope, wantStatus := range map[string]int{"orders:write": http.StatusNoContent, "orders:delete": http.StatusForbidden} {
		handler := verifier.Middleware(RequireScope(scope)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})))
		request := httptest.NewRequest(http.MethodDelete, "/orders/1", nil)
		request.Header.Set("Authorization", token)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != wantStatus {
			t.Errorf("RequireScope(%q): status %d, want %d", scope, recorder.Code, wantStatus)
		}
		if wantStatus == http.StatusForbidden && recorder.Header().Get("WWW-Authenticate") != `Bearer error="insufficient_scope", scope="orders:delete"` {
			t.Errorf("challenge = %q", recorder.Header().Get("WWW-Authenticate"))
		}
	}
	recorder := httptest.NewRecorder()
	RequireScope("orders:read")(http.NotFoundHandler()).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("RequireScope without Middleware: status %d, want 401", recorder.Code)
	}
}

func TestFromContext_WithoutMiddleware_ReportsAbsence(t *testing.T) {
	if claims, isPresent := FromContext(httptest.NewRequest(http.MethodGet, "/", nil).Context()); isPresent || claims != nil {
		t.Fatalf("FromContext() = %+v, %v; want nothing", claims, isPresent)
	}
}

func TestMiddleware_PackageLevel_PanicsOnInvalidConfiguration(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Middleware with an http issuer must panic at setup")
		}
	}()
	Middleware("http://auth.example.com", "api_orders")
}
