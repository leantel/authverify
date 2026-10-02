// Package authverify verifies Leantel access tokens (RS256 JWTs, RFC 9068) in Go services.
//
// It checks the signature against the issuer's JWKS (cached per its Cache-Control header within
// 1 minute to 24 hours, refetched at most once a minute for an unknown kid, served stale for at most
// 1 hour while the JWKS is unreachable), the exact issuer, the expected audience, exp/nbf/iat with
// 60 seconds of leeway, the at+jwt token type, and the presence of the sub, jti, client_id and tenant_id claims.
package authverify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	clockLeeway          = 60 * time.Second
	jwksPath             = "/.well-known/jwks.json"
	maximumRedirects     = 3
	defaultClientTimeout = 10 * time.Second
)

var accessTokenTypes = []string{"at+jwt", "application/at+jwt"}

// ErrInvalidToken wraps every reason a token is rejected.
var ErrInvalidToken = errors.New("invalid token")

// Verifier checks access tokens for one issuer and one audience. It is safe for concurrent use.
type Verifier struct {
	issuer   string
	audience string
	keys     *keySet
	parser   *jwt.Parser
}

type settings struct {
	httpClient *http.Client
	jwksURL    string
	now        func() time.Time
}

// Option configures a Verifier.
type Option func(*settings)

// WithHTTPClient sets the client used to fetch the JWKS. Its redirect policy is replaced by one that
// follows at most 3 redirects and never leaves https.
func WithHTTPClient(client *http.Client) Option {
	return func(s *settings) { s.httpClient = client }
}

// WithJWKSURL overrides the JWKS location (default: issuer + /.well-known/jwks.json). It must use https
// (http only for localhost).
func WithJWKSURL(jwksURL string) Option {
	return func(s *settings) { s.jwksURL = jwksURL }
}

// WithClock sets the time source, for tests.
func WithClock(now func() time.Time) Option {
	return func(s *settings) { s.now = now }
}

// NewVerifier returns a Verifier for tokens issued by issuer (exact, https; http only for localhost)
// and meant for audience (your API's aud, e.g. "api_orders").
func NewVerifier(issuer string, audience string, options ...Option) (*Verifier, error) {
	if err := validateIssuer(issuer); err != nil {
		return nil, err
	}
	if audience == "" {
		return nil, errors.New("authverify: audience is required")
	}
	configured := settings{httpClient: &http.Client{Timeout: defaultClientTimeout}, jwksURL: issuer + jwksPath, now: time.Now}
	for _, option := range options {
		option(&configured)
	}
	if configured.httpClient == nil || configured.now == nil {
		return nil, errors.New("authverify: WithHTTPClient and WithClock need a non-nil value")
	}
	if err := validateEndpoint(configured.jwksURL); err != nil {
		return nil, fmt.Errorf("authverify: JWKS URL: %w", err)
	}
	httpClient := *configured.httpClient
	httpClient.CheckRedirect = refuseUnsafeRedirect
	return &Verifier{
		issuer: issuer, audience: audience,
		keys: &keySet{url: configured.jwksURL, httpClient: &httpClient, now: configured.now},
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(issuer), jwt.WithAudience(audience),
			jwt.WithLeeway(clockLeeway), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(configured.now),
		),
	}, nil
}

// Verify checks the token and returns its claims, or an error wrapping ErrInvalidToken.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	claims := &Claims{}
	_, err := v.parser.ParseWithClaims(token, claims, func(parsed *jwt.Token) (any, error) {
		if err := checkHeader(parsed.Header); err != nil {
			return nil, err
		}
		keyID, _ := parsed.Header["kid"].(string)
		return v.keys.publicKey(ctx, keyID)
	})
	if err == nil {
		err = checkRequiredClaims(claims)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return claims, nil
}

func checkHeader(header map[string]any) error {
	tokenType, _ := header["typ"].(string)
	isAccessToken := false
	for _, accepted := range accessTokenTypes {
		isAccessToken = isAccessToken || strings.EqualFold(tokenType, accepted)
	}
	if !isAccessToken {
		return errors.New("token type must be at+jwt")
	}
	if keyID, _ := header["kid"].(string); keyID == "" {
		return errors.New("token has no kid")
	}
	return nil
}

func checkRequiredClaims(claims *Claims) error {
	var missing []string
	for name, value := range map[string]string{"sub": claims.Subject, "jti": claims.ID, "client_id": claims.ClientID, "tenant_id": claims.TenantID} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if claims.IssuedAt == nil {
		missing = append(missing, "iat")
	}
	if len(missing) > 0 {
		return fmt.Errorf("token is missing required claims: %s", strings.Join(missing, ", "))
	}
	return nil
}

func validateIssuer(issuer string) error {
	if strings.HasSuffix(issuer, "/") {
		return errors.New("authverify: issuer must not end with a slash")
	}
	if err := validateEndpoint(issuer); err != nil {
		return fmt.Errorf("authverify: issuer: %w", err)
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("must be an absolute URL without credentials, query or fragment")
	}
	return checkScheme(parsed)
}

func checkScheme(parsed *url.URL) error {
	hostname := parsed.Hostname()
	isLoopback := hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopback) {
		return errors.New("must use https (http only for localhost)")
	}
	return nil
}

func refuseUnsafeRedirect(request *http.Request, previous []*http.Request) error {
	if len(previous) > maximumRedirects {
		return errors.New("too many JWKS redirects")
	}
	return checkScheme(request.URL)
}
