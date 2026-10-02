package authverify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testAudience = "api_orders"
	testKeyID    = "k-20261002-1"
)

var testNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type testIssuer struct {
	server       *httptest.Server
	privateKey   *rsa.PrivateKey
	fetches      atomic.Int32
	isFailing    atomic.Bool
	cacheControl string
	keyIDs       []string
	extraKeys    []map[string]string
	release      chan struct{}
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	issuer := &testIssuer{privateKey: newRSAKey(t), keyIDs: []string{testKeyID}, cacheControl: "public, max-age=300"}
	issuer.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		issuer.fetches.Add(1)
		if issuer.release != nil {
			<-issuer.release
		}
		if issuer.isFailing.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		keys := append([]map[string]string{}, issuer.extraKeys...)
		for _, keyID := range issuer.keyIDs {
			keys = append(keys, map[string]string{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": keyID,
				"n": base64.RawURLEncoding.EncodeToString(issuer.privateKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(issuer.privateKey.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", issuer.cacheControl)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(issuer.server.Close)
	return issuer
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return privateKey
}

func (i *testIssuer) url() string {
	return i.server.URL
}

func (i *testIssuer) validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": i.url(), "sub": "usr_1", "aud": testAudience, "exp": testNow.Add(15 * time.Minute).Unix(),
		"iat": testNow.Unix(), "jti": "tok_1", "client_id": "cli_1", "tenant_id": "ten_1",
		"scope": "openid orders:read orders:write", "roles": []string{"viewer"}, "utype": "customer", "authz_ver": 3,
	}
}

func (i *testIssuer) sign(t *testing.T, claims jwt.MapClaims, headers map[string]any, privateKey *rsa.PrivateKey) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKeyID
	token.Header["typ"] = "at+jwt"
	for name, value := range headers {
		if value == nil {
			delete(token.Header, name)
			continue
		}
		token.Header[name] = value
	}
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func newTestVerifier(t *testing.T, issuer *testIssuer, now *time.Time) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(issuer.url(), testAudience,
		WithJWKSURL(issuer.url()+"/.well-known/jwks.json"), WithHTTPClient(issuer.server.Client()),
		WithClock(func() time.Time { return *now }))
	if err != nil {
		t.Fatalf("NewVerifier(): %v", err)
	}
	return verifier
}

func TestVerify_ValidAccessToken_ReturnsAllT1Claims(t *testing.T) {
	issuer := newTestIssuer(t)
	now := testNow
	claims, err := newTestVerifier(t, issuer, &now).Verify(context.Background(), issuer.sign(t, issuer.validClaims(), nil, issuer.privateKey))
	if err != nil {
		t.Fatalf("Verify(): %v", err)
	}
	if claims.Subject != "usr_1" || claims.TenantID != "ten_1" || claims.ClientID != "cli_1" || claims.UserType != "customer" ||
		claims.AuthorizationVersion != 3 || len(claims.Roles) != 1 || !claims.HasScope("orders:write") || claims.HasScope("orders:delete") {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestVerify_RejectsEveryS2TokenAttack(t *testing.T) {
	issuer := newTestIssuer(t)
	foreignKey := newRSAKey(t)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&issuer.privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	hmacToken := jwt.NewWithClaims(jwt.SigningMethodHS256, issuer.validClaims())
	hmacToken.Header["kid"], hmacToken.Header["typ"] = testKeyID, "at+jwt"
	hmacSigned, err := hmacToken.SignedString(publicKeyBytes)
	if err != nil {
		t.Fatalf("sign HS256: %v", err)
	}
	valid := issuer.sign(t, issuer.validClaims(), nil, issuer.privateKey)
	validParts := strings.Split(valid, ".")
	tamperedClaims := issuer.validClaims()
	tamperedClaims["tenant_id"] = "ten_other"
	tamperedPayload, _ := json.Marshal(tamperedClaims)
	withClaim := func(name string, value any) jwt.MapClaims {
		claims := issuer.validClaims()
		claims[name] = value
		return claims
	}
	attacks := map[string]string{
		"alg none":                    unsignedToken(t, issuer.validClaims()),
		"HS256 with our public key":   hmacSigned,
		"foreign key with our kid":    issuer.sign(t, issuer.validClaims(), nil, foreignKey),
		"edited payload":              validParts[0] + "." + base64.RawURLEncoding.EncodeToString(tamperedPayload) + "." + validParts[2],
		"wrong issuer":                issuer.sign(t, withClaim("iss", "https://evil.example"), nil, issuer.privateKey),
		"issuer with trailing slash":  issuer.sign(t, withClaim("iss", issuer.url()+"/"), nil, issuer.privateKey),
		"wrong audience":              issuer.sign(t, withClaim("aud", "api_billing"), nil, issuer.privateKey),
		"expired beyond leeway":       issuer.sign(t, withClaim("exp", testNow.Add(-61*time.Second).Unix()), nil, issuer.privateKey),
		"no expiry":                   issuer.sign(t, withClaim("exp", nil), nil, issuer.privateKey),
		"not yet valid beyond leeway": issuer.sign(t, withClaim("nbf", testNow.Add(61*time.Second).Unix()), nil, issuer.privateKey),
		"issued in the future":        issuer.sign(t, withClaim("iat", testNow.Add(61*time.Second).Unix()), nil, issuer.privateKey),
		"ID token type":               issuer.sign(t, issuer.validClaims(), map[string]any{"typ": "JWT"}, issuer.privateKey),
		"missing type":                issuer.sign(t, issuer.validClaims(), map[string]any{"typ": nil}, issuer.privateKey),
		"missing kid":                 issuer.sign(t, issuer.validClaims(), map[string]any{"kid": nil}, issuer.privateKey),
		"unknown kid":                 issuer.sign(t, issuer.validClaims(), map[string]any{"kid": "k-20991231-1"}, issuer.privateKey),
		"not a JWT":                   "not-a-token",
	}
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	for name, token := range attacks {
		if claims, err := verifier.Verify(context.Background(), token); err == nil || !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: Verify() = %+v, %v; want ErrInvalidToken", name, claims, err)
		}
	}
}

func TestVerify_ClockSkewWithin60SecondsIsAccepted(t *testing.T) {
	issuer := newTestIssuer(t)
	claims := issuer.validClaims()
	claims["exp"] = testNow.Add(-59 * time.Second).Unix()
	claims["nbf"] = testNow.Add(59 * time.Second).Unix()
	now := testNow
	if _, err := newTestVerifier(t, issuer, &now).Verify(context.Background(), issuer.sign(t, claims, nil, issuer.privateKey)); err != nil {
		t.Fatalf("Verify() inside the 60 s leeway = %v, want accepted", err)
	}
}

func TestVerify_UnknownKid_RefetchesAtMostOncePerMinute(t *testing.T) {
	issuer := newTestIssuer(t)
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	unknown := issuer.sign(t, issuer.validClaims(), map[string]any{"kid": "k-20991231-1"}, issuer.privateKey)
	for range 5 {
		_, _ = verifier.Verify(context.Background(), unknown)
	}
	if fetches := issuer.fetches.Load(); fetches != 1 {
		t.Fatalf("JWKS fetches after 5 unknown-kid tokens = %d, want 1 (refetch at most once a minute)", fetches)
	}
	issuer.keyIDs = append(issuer.keyIDs, "k-20991231-1")
	now = now.Add(61 * time.Second)
	if _, err := verifier.Verify(context.Background(), unknown); err != nil {
		t.Fatalf("Verify() after the rotated key was published = %v, want accepted", err)
	}
	if fetches := issuer.fetches.Load(); fetches != 2 {
		t.Fatalf("JWKS fetches = %d, want 2", fetches)
	}
}

func TestVerify_JWKSIsCachedPerCacheControl(t *testing.T) {
	issuer := newTestIssuer(t)
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	token := issuer.sign(t, issuer.validClaims(), nil, issuer.privateKey)
	for range 3 {
		if _, err := verifier.Verify(context.Background(), token); err != nil {
			t.Fatalf("Verify(): %v", err)
		}
	}
	now = now.Add(299 * time.Second)
	_, _ = verifier.Verify(context.Background(), token)
	if fetches := issuer.fetches.Load(); fetches != 1 {
		t.Fatalf("fetches within max-age = %d, want 1", fetches)
	}
	now = now.Add(2 * time.Second)
	_, _ = verifier.Verify(context.Background(), token)
	if fetches := issuer.fetches.Load(); fetches != 2 {
		t.Fatalf("fetches after max-age = %d, want 2", fetches)
	}
}

func TestNewVerifier_RejectsInvalidConfiguration(t *testing.T) {
	for name, arguments := range map[string][2]string{
		"empty issuer":   {"", testAudience},
		"http issuer":    {"http://auth.example.com", testAudience},
		"trailing slash": {"https://auth.example.com/", testAudience},
		"empty audience": {"https://auth.example.com", ""},
	} {
		if _, err := NewVerifier(arguments[0], arguments[1]); err == nil {
			t.Errorf("%s: NewVerifier() = nil error", name)
		}
	}
}

func unsignedToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	token.Header["kid"], token.Header["typ"] = testKeyID, "at+jwt"
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	return signed
}

func TestVerify_RejectsTokensMissingRequiredClaims(t *testing.T) {
	issuer := newTestIssuer(t)
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	for _, name := range []string{"sub", "jti", "client_id", "tenant_id", "iat"} {
		for _, value := range []any{nil, ""} {
			if name == "iat" && value != nil {
				continue
			}
			claims := issuer.validClaims()
			claims[name] = value
			if value == nil {
				delete(claims, name)
			}
			_, err := verifier.Verify(context.Background(), issuer.sign(t, claims, nil, issuer.privateKey))
			if !errors.Is(err, ErrInvalidToken) || !strings.Contains(err.Error(), name) {
				t.Errorf("token with %s=%v: Verify() = %v, want ErrInvalidToken naming %s", name, value, err, name)
			}
		}
	}
}

func TestVerify_AcceptsTheMediaTypeFormOfAtJWT(t *testing.T) {
	issuer := newTestIssuer(t)
	now := testNow
	token := issuer.sign(t, issuer.validClaims(), map[string]any{"typ": "application/at+jwt"}, issuer.privateKey)
	if _, err := newTestVerifier(t, issuer, &now).Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify() with typ application/at+jwt (RFC 9068 §4) = %v, want accepted", err)
	}
}

func TestVerify_IgnoresWeakOrMalformedJWKSKeys(t *testing.T) {
	issuer := newTestIssuer(t)
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encode := func(value *big.Int) string { return base64.RawURLEncoding.EncodeToString(value.Bytes()) }
	strongModulus := encode(issuer.privateKey.N)
	issuer.extraKeys = []map[string]string{
		{"kty": "RSA", "kid": "weak", "n": encode(weakKey.N), "e": "AQAB"},
		{"kty": "RSA", "kid": "even-exponent", "n": strongModulus, "e": encode(big.NewInt(4))},
		{"kty": "RSA", "kid": "exponent-one", "n": strongModulus, "e": "AQ"},
		{"kty": "RSA", "kid": "huge-exponent", "n": strongModulus, "e": encode(new(big.Int).Lsh(big.NewInt(1), 40))},
		{"kty": "RSA", "kid": "bad-base64", "n": "!!", "e": "AQAB"},
		{"kty": "RSA", "kid": "encryption", "use": "enc", "n": strongModulus, "e": "AQAB"},
		{"kty": "EC", "kid": "elliptic", "n": strongModulus, "e": "AQAB"},
	}
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	for _, keyID := range []string{"weak", "even-exponent", "exponent-one", "huge-exponent", "bad-base64", "encryption", "elliptic"} {
		privateKey := issuer.privateKey
		if keyID == "weak" {
			privateKey = weakKey
		}
		if _, err := verifier.Verify(context.Background(), issuer.sign(t, issuer.validClaims(), map[string]any{"kid": keyID}, privateKey)); err == nil {
			t.Errorf("kid %s: Verify() accepted a token signed with a key that should have been ignored", keyID)
		}
	}
}

func TestVerify_JWKSFailures_BackOffAndFailClosedAfterAnHourStale(t *testing.T) {
	issuer := newTestIssuer(t)
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	longLived := issuer.validClaims()
	longLived["exp"] = testNow.Add(3 * time.Hour).Unix()
	token := issuer.sign(t, longLived, nil, issuer.privateKey)
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify(): %v", err)
	}
	issuer.isFailing.Store(true)
	now = now.Add(5 * time.Minute)
	for range 5 {
		if _, err := verifier.Verify(context.Background(), token); err != nil {
			t.Fatalf("Verify() with expired cache and JWKS down = %v, want the stale key served", err)
		}
	}
	if fetches := issuer.fetches.Load(); fetches != 2 {
		t.Fatalf("fetches = %d, want 2 (failures retried at most once a minute)", fetches)
	}
	now = testNow.Add(5*time.Minute + time.Hour)
	if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, errJWKSUnavailable) {
		t.Fatalf("Verify() an hour past expiry with JWKS down = %v, want fail closed", err)
	}
	issuer.isFailing.Store(false)
	now = now.Add(time.Minute)
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify() after the JWKS recovered = %v", err)
	}
}

func TestVerify_ColdJWKSFailure_RetriesAtMostOncePerSecond(t *testing.T) {
	issuer := newTestIssuer(t)
	issuer.isFailing.Store(true)
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	token := issuer.sign(t, issuer.validClaims(), nil, issuer.privateKey)
	for range 5 {
		if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, errJWKSUnavailable) {
			t.Fatalf("Verify() with no JWKS = %v, want unavailable", err)
		}
	}
	issuer.isFailing.Store(false)
	now = now.Add(time.Second)
	if _, err := verifier.Verify(context.Background(), token); err != nil || issuer.fetches.Load() != 2 {
		t.Fatalf("Verify() = %v after %d fetches, want success on the 2nd fetch", err, issuer.fetches.Load())
	}
}

func TestVerify_ConcurrentColdRequests_ShareOneFetch(t *testing.T) {
	issuer := newTestIssuer(t)
	issuer.release = make(chan struct{})
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	token := issuer.sign(t, issuer.validClaims(), nil, issuer.privateKey)
	results := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := verifier.Verify(context.Background(), token)
			results <- err
		}()
	}
	for issuer.fetches.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(issuer.release)
	for range 8 {
		if err := <-results; err != nil {
			t.Fatalf("Verify(): %v", err)
		}
	}
	if fetches := issuer.fetches.Load(); fetches != 1 {
		t.Fatalf("fetches = %d, want 1 shared fetch", fetches)
	}
}

func TestVerify_WaitingForAFetch_HonoursCancellation(t *testing.T) {
	issuer := newTestIssuer(t)
	issuer.release = make(chan struct{})
	defer close(issuer.release)
	now := testNow
	verifier := newTestVerifier(t, issuer, &now)
	token := issuer.sign(t, issuer.validClaims(), nil, issuer.privateKey)
	go func() { _, _ = verifier.Verify(context.Background(), token) }()
	for issuer.fetches.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.Verify(ctx, token); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify() with a cancelled context while a fetch is in flight = %v, want context.Canceled", err)
	}
}

func TestCacheLifetime_IsClampedBetweenAMinuteAndADay(t *testing.T) {
	for cacheControl, want := range map[string]time.Duration{
		"":                             5 * time.Minute,
		"public, max-age=300":          5 * time.Minute,
		"Public, MAX-AGE=600":          10 * time.Minute,
		"max-age=0":                    time.Minute,
		"no-store":                     time.Minute,
		"no-cache, max-age=600":        time.Minute,
		"max-age=99999999999999999":    24 * time.Hour,
		"max-age=99999999999999999999": 5 * time.Minute,
		"max-age=9223372036854775807":  24 * time.Hour,
		"max-age=-5":                   time.Minute,
		"max-age=abc":                  5 * time.Minute,
	} {
		if got := cacheLifetime(cacheControl); got != want {
			t.Errorf("cacheLifetime(%q) = %v, want %v", cacheControl, got, want)
		}
	}
}

func TestNewVerifier_RejectsUnsafeOptions(t *testing.T) {
	for name, option := range map[string]Option{
		"nil client":         WithHTTPClient(nil),
		"nil clock":          WithClock(nil),
		"http JWKS":          WithJWKSURL("http://auth.example.com/.well-known/jwks.json"),
		"relative JWKS":      WithJWKSURL("/.well-known/jwks.json"),
		"JWKS with userinfo": WithJWKSURL("https://user:pass@auth.example.com/jwks.json"),
	} {
		if _, err := NewVerifier("https://auth.example.com", testAudience, option); err == nil {
			t.Errorf("%s: NewVerifier() = nil error", name)
		}
	}
	if _, err := NewVerifier("https://auth.example.com", testAudience, WithJWKSURL("http://localhost:8080/.well-known/jwks.json")); err != nil {
		t.Errorf("localhost http JWKS: NewVerifier() = %v, want accepted", err)
	}
}

func TestVerify_JWKSRedirectToHTTP_IsRefused(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(plain.Close)
	redirecting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(plain.URL, "127.0.0.1", "example.com", 1), http.StatusFound)
	}))
	t.Cleanup(redirecting.Close)
	verifier, err := NewVerifier("https://auth.example.com", testAudience, WithJWKSURL(redirecting.URL), WithHTTPClient(redirecting.Client()))
	if err != nil {
		t.Fatalf("NewVerifier(): %v", err)
	}
	_, err = verifier.keys.publicKey(context.Background(), testKeyID)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("publicKey() after a redirect to http = %v, want the redirect refused", err)
	}
}
