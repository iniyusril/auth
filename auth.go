package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
)

// JWTMiddleware struct
type JWTMiddleware struct {
	SecretKey    string            `json:"secret_key,omitempty"`
	ExcludePaths map[string]string `json:"exclude_paths,omitempty"` // Maps path -> method
}

// Register Caddy module
func init() {
	caddy.RegisterModule(JWTMiddleware{})
}

// CaddyModule returns the module information.
func (JWTMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "gmi.auth",
		New: func() caddy.Module { return new(JWTMiddleware) },
	}
}

// Provision initializes the middleware
func (m *JWTMiddleware) Provision(ctx caddy.Context) error {
	if m.SecretKey == "" {
		return fmt.Errorf("JWT secret key is required")
	}
	if m.ExcludePaths == nil {
		m.ExcludePaths = make(map[string]string)
	}
	return nil
}

// ServeHTTP handles the request
func (m JWTMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Skip excluded paths with specific methods
	for path, method := range m.ExcludePaths {
		if strings.HasPrefix(r.URL.Path, path) && (method == "*" || method == r.Method) {
			return next.ServeHTTP(w, r)
		}
	}

	// Extract token from Authorization header
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tokenString == "" {
		http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
		return nil
	}

	// Validate JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(m.SecretKey), nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		http.Error(w, "Unauthorized: Missing Claims", http.StatusUnauthorized)
		return nil
	}

	data, err := json.Marshal(claims)

	if err != nil {
		http.Error(w, "error marshal claims", http.StatusUnauthorized)
	}

	w.Header().Set("context", string(data))

	// Proceed to next handler
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile configures from Caddyfile
func (m *JWTMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	m.ExcludePaths = make(map[string]string)
	for d.Next() {
		for d.NextBlock(0) {
			key := d.Val()
			switch key {
			case "secret_key":
				if !d.Args(&m.SecretKey) {
					return d.Err("invalid secret_key")
				}
			case "exclude_paths":
				var path, method string
				if !d.Args(&path, &method) {
					return d.Err("invalid exclude_paths format, expected: path method")
				}
				m.ExcludePaths[path] = method
			default:
				return d.Errf("unknown directive: %s", key)
			}
		}
	}
	return nil
}
