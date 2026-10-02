package authverify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type contextKey struct{}

// Middleware returns net/http middleware that requires a valid Bearer access token for issuer and audience.
// It panics if issuer, audience or an option is invalid, since that is a programming error found at startup.
func Middleware(issuer string, audience string, options ...Option) func(http.Handler) http.Handler {
	verifier, err := NewVerifier(issuer, audience, options...)
	if err != nil {
		panic(err)
	}
	return verifier.Middleware
}

// Middleware rejects requests without a valid Bearer token with 401 (RFC 6750 §3) and otherwise stores
// the claims in the request context for FromContext.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, hasCredentials := bearerToken(r.Header.Get("Authorization"))
		if !hasCredentials {
			writeChallenge(w, http.StatusUnauthorized, `Bearer`, "", "a Bearer access token is required")
			return
		}
		claims, err := v.Verify(r.Context(), token)
		if err != nil {
			writeChallenge(w, http.StatusUnauthorized, `Bearer error="invalid_token"`, "invalid_token", "the access token is invalid or expired")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, claims)))
	})
}

// RequireScope returns middleware, to run after Middleware, that answers 403 insufficient_scope
// (RFC 6750 §3.1) unless the token's scope claim contains scope.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, isPresent := FromContext(r.Context())
			if !isPresent {
				writeChallenge(w, http.StatusUnauthorized, `Bearer`, "", "a Bearer access token is required")
				return
			}
			if !claims.HasScope(scope) {
				challenge := fmt.Sprintf(`Bearer error="insufficient_scope", scope=%q`, scope)
				writeChallenge(w, http.StatusForbidden, challenge, "insufficient_scope", "the access token lacks the required scope")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// FromContext returns the claims stored by Middleware.
func FromContext(ctx context.Context) (*Claims, bool) {
	claims, isPresent := ctx.Value(contextKey{}).(*Claims)
	return claims, isPresent
}

func bearerToken(authorization string) (string, bool) {
	scheme, token, hasToken := strings.Cut(strings.TrimSpace(authorization), " ")
	token = strings.TrimSpace(token)
	if !hasToken || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

func writeChallenge(w http.ResponseWriter, status int, challenge string, code string, description string) {
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]string{"error_description": description}
	if code != "" {
		body["error"] = code
	}
	_ = json.NewEncoder(w).Encode(body)
}
