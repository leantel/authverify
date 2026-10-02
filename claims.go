package authverify

import (
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are the verified claims of a Leantel access token (RFC 9068).
type Claims struct {
	jwt.RegisteredClaims
	ClientID             string   `json:"client_id"`
	TenantID             string   `json:"tenant_id"`
	Scope                string   `json:"scope"`
	Roles                []string `json:"roles,omitempty"`
	UserType             string   `json:"utype,omitempty"`
	AuthorizationVersion int64    `json:"authz_ver"`
}

// Scopes returns the space-separated scope claim as a list.
func (c *Claims) Scopes() []string {
	return strings.Fields(c.Scope)
}

// HasScope reports whether the scope claim contains scope exactly, e.g. "orders:read". OIDC scopes
// such as "openid" and API permissions share the claim.
func (c *Claims) HasScope(scope string) bool {
	return slices.Contains(c.Scopes(), scope)
}
