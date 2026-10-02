# authverify

Verify Leantel access tokens in Go services: RS256, JWKS caching, `typ: at+jwt`, net/http middleware.

```sh
go get github.com/leantel/authverify
```

```go
protect := authverify.Middleware("https://auth.example.com", "api_orders")
http.Handle("/orders", protect(authverify.RequireScope("orders:read")(ordersHandler)))

func ordersHandler(w http.ResponseWriter, r *http.Request) {
	claims, _ := authverify.FromContext(r.Context())
	// claims.Subject is the user id, claims.TenantID the tenant: never take a tenant id from the request.
}
```

Or verify a token yourself:

```go
verifier, err := authverify.NewVerifier("https://auth.example.com", "api_orders")
claims, err := verifier.Verify(ctx, token) // errors wrap authverify.ErrInvalidToken
```

## What is checked

- Algorithm is RS256 only (`none`, HMAC and others are rejected).
- `kid` must be in the issuer's JWKS (`<issuer>/.well-known/jwks.json`), cached per its `Cache-Control`
  (clamped to 1 minute – 24 hours); an unknown `kid` triggers at most one refetch per minute.
  Only RSA signing keys of at least 2048 bits are used.
- Signature, exact `iss`, `aud` containing your audience, `exp` (required), `nbf` and `iat` (required) with 60 s leeway.
- Header `typ` must be `at+jwt` or `application/at+jwt` (RFC 9068), so ID tokens are never accepted as access tokens.
- `sub`, `jti`, `client_id` and `tenant_id` must be present.
- The issuer and JWKS URL must be https (`http://localhost` is allowed for local development); JWKS redirects never leave https.

Responses follow RFC 6750: no credentials → `401` with `WWW-Authenticate: Bearer`; a bad token → `401` with
`error="invalid_token"`; `RequireScope` → `403` with `error="insufficient_scope"`. All carry `Cache-Control: no-store`.

If the JWKS can't be fetched, cached keys keep working for up to 1 hour past their cache lifetime, then
verification fails closed until the issuer is reachable again. Concurrent requests share one fetch.

## License

Apache-2.0
