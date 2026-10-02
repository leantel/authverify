package authverify

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultCacheLifetime  = 5 * time.Minute
	minimumCacheLifetime  = time.Minute
	maximumCacheLifetime  = 24 * time.Hour
	warmRefetchGap        = time.Minute
	coldRetryGap          = time.Second
	maximumStaleness      = time.Hour
	fetchTimeout          = 10 * time.Second
	maximumJWKSBodyLength = 1 << 20
	minimumModulusBits    = 2048
	minimumExponent       = 3
	maximumExponent       = 1<<31 - 1
)

var errJWKSUnavailable = errors.New("JWKS unavailable")

type jsonWebKey struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

type keySet struct {
	url         string
	httpClient  *http.Client
	now         func() time.Time
	mutex       sync.Mutex
	keys        map[string]*rsa.PublicKey
	expiresAt   time.Time
	attemptedAt time.Time
	lastError   error
	inFlight    chan struct{}
}

func (s *keySet) publicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for {
		key, isKnown := s.keys[keyID]
		if s.inFlight != nil && !isKnown {
			if err := s.waitForFetch(ctx); err != nil {
				return nil, err
			}
			continue
		}
		now := s.now()
		if s.shouldFetch(now, isKnown) {
			s.fetchUnlocked(ctx, now)
			continue
		}
		if s.keys == nil || !now.Before(s.expiresAt.Add(maximumStaleness)) {
			return nil, errors.Join(errJWKSUnavailable, s.lastError)
		}
		if !isKnown {
			return nil, fmt.Errorf("unknown kid %q", keyID)
		}
		return key, nil
	}
}

func (s *keySet) shouldFetch(now time.Time, isKnown bool) bool {
	if s.inFlight != nil {
		return false
	}
	retryGap := warmRefetchGap
	if s.keys == nil {
		retryGap = coldRetryGap
	}
	if !s.attemptedAt.IsZero() && now.Sub(s.attemptedAt) < retryGap {
		return false
	}
	return s.keys == nil || !isKnown || !now.Before(s.expiresAt)
}

func (s *keySet) waitForFetch(ctx context.Context) error {
	done := s.inFlight
	s.mutex.Unlock()
	defer s.mutex.Lock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for JWKS: %w", ctx.Err())
	}
}

func (s *keySet) fetchUnlocked(ctx context.Context, now time.Time) {
	s.attemptedAt = now
	done := make(chan struct{})
	s.inFlight = done
	s.mutex.Unlock()
	keys, lifetime, err := s.fetch(ctx)
	s.mutex.Lock()
	if err == nil {
		s.keys, s.expiresAt, s.lastError = keys, s.now().Add(lifetime), nil
	} else {
		s.lastError = err
	}
	s.inFlight = nil
	close(done)
}

func (s *keySet) fetch(ctx context.Context) (map[string]*rsa.PublicKey, time.Duration, error) {
	// Why: one fetch serves every waiting request, so the first caller cancelling must not fail the others.
	fetchContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(fetchContext, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build JWKS request: %w", err)
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("fetch JWKS: status %d", response.StatusCode)
	}
	var document struct {
		Keys []jsonWebKey `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, response.Body, maximumJWKSBodyLength)).Decode(&document); err != nil {
		return nil, 0, fmt.Errorf("decode JWKS: %w", err)
	}
	return rsaSigningKeys(document.Keys), cacheLifetime(response.Header.Get("Cache-Control")), nil
}

func rsaSigningKeys(keys []jsonWebKey) map[string]*rsa.PublicKey {
	publicKeys := map[string]*rsa.PublicKey{}
	for _, key := range keys {
		isSigningKey := key.KeyType == "RSA" && (key.Use == "" || key.Use == "sig") && (key.Algorithm == "" || key.Algorithm == "RS256")
		if !isSigningKey || key.KeyID == "" {
			continue
		}
		if publicKey, isValid := parseRSAKey(key); isValid {
			publicKeys[key.KeyID] = publicKey
		}
	}
	return publicKeys
}

func parseRSAKey(key jsonWebKey) (*rsa.PublicKey, bool) {
	modulusBytes, modulusErr := base64.RawURLEncoding.DecodeString(key.Modulus)
	exponentBytes, exponentErr := base64.RawURLEncoding.DecodeString(key.Exponent)
	if modulusErr != nil || exponentErr != nil {
		return nil, false
	}
	modulus := new(big.Int).SetBytes(modulusBytes)
	exponent := new(big.Int).SetBytes(exponentBytes)
	isValidExponent := exponent.IsInt64() && exponent.Int64() >= minimumExponent && exponent.Int64() <= maximumExponent && exponent.Bit(0) == 1
	if modulus.BitLen() < minimumModulusBits || !isValidExponent {
		return nil, false
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, true
}

func cacheLifetime(cacheControl string) time.Duration {
	lifetime := defaultCacheLifetime
	for directive := range strings.SplitSeq(strings.ToLower(cacheControl), ",") {
		directive = strings.TrimSpace(directive)
		if directive == "no-store" || directive == "no-cache" {
			return minimumCacheLifetime
		}
		value, isMaxAge := strings.CutPrefix(directive, "max-age=")
		if seconds, err := strconv.ParseInt(value, 10, 64); isMaxAge && err == nil {
			lifetime = time.Duration(min(max(seconds, 0), int64(maximumCacheLifetime/time.Second))) * time.Second
		}
	}
	return min(max(lifetime, minimumCacheLifetime), maximumCacheLifetime)
}
