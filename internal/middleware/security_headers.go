package middleware

import "net/http"

// SecurityHeadersConfig holds security headers configuration
type SecurityHeadersConfig struct {
	Env string
}

// SecurityHeaders returns a middleware that adds security headers to all responses
func SecurityHeaders(config SecurityHeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// X-Frame-Options: Clickjacking protection
			// DENY prevents the page from being framed at all
			w.Header().Set("X-Frame-Options", "DENY")

			// X-Content-Type-Options: MIME sniffing prevention
			// nosniff prevents browsers from MIME-sniffing a response away from declared Content-Type
			w.Header().Set("X-Content-Type-Options", "nosniff")

			// X-XSS-Protection: Legacy XSS protection header (for older browsers)
			// 1; mode=block enables XSS filtering and blocks the page if XSS is detected
			w.Header().Set("X-XSS-Protection", "1; mode=block")

			// Referrer-Policy: Controls how much referrer information is shared
			// strict-origin-when-cross-origin: sends referrer only for same-origin requests
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Content-Security-Policy: Controls resource loading (XSS prevention)
			// Production vs Development CSP policies
			var csp string
			if config.Env == "production" {
				// Strict CSP for production - restricts inline scripts and styles
				csp = "default-src 'self'; " +
					"script-src 'self'; " +
					"style-src 'self' 'unsafe-inline'; " +
					"img-src 'self' data: https:; " +
					"font-src 'self'; " +
					"connect-src 'self'; " +
					"frame-ancestors 'none'; " +
					"base-uri 'self'; " +
					"form-action 'self'"
			} else {
				// More lenient CSP for development to allow hot reloading
				csp = "default-src 'self' http: https: ws:; " +
					"script-src 'self' 'unsafe-inline' 'unsafe-eval' http: https: ws:; " +
					"style-src 'self' 'unsafe-inline' http: https:; " +
					"img-src 'self' data: https: http:; " +
					"font-src 'self' data: http: https:; " +
					"connect-src 'self' http: https: ws: wss:; " +
					"frame-ancestors 'self'; " +
					"base-uri 'self'; " +
					"form-action 'self'"
			}
			w.Header().Set("Content-Security-Policy", csp)

			// Strict-Transport-Security: HTTPS enforcement (HSTS)
			// Only send for HTTPS connections in production
			if config.Env == "production" && (r.Header.Get("X-Forwarded-Proto") == "https" || r.URL.Scheme == "https") {
				// max-age: 31536000 seconds (1 year)
				// includeSubDomains: applies to all subdomains
				// preload: allows inclusion in HSTS preload lists
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			}

			// Permissions-Policy: Controls browser features (formerly Feature-Policy)
			// Restricts access to sensitive browser APIs
			w.Header().Set("Permissions-Policy",
				"accelerometer=(), "+
					"camera=(), "+
					"geolocation=(), "+
					"gyroscope=(), "+
					"magnetometer=(), "+
					"microphone=(), "+
					"payment=(), "+
					"usb=()",
			)

			// X-DNS-Prefetch-Control: Prevents DNS prefetching to avoid information leakage
			w.Header().Set("X-DNS-Prefetch-Control", "off")

			// Cross-Origin-Embedder-Policy: Controls resource embedding
			// Production: require-corp (strict isolation)
			// Development: credentialless (allows third-party resources for tooling)
			if config.Env == "production" {
				w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
			} else {
				w.Header().Set("Cross-Origin-Embedder-Policy", "credentialless")
			}

			// Cross-Origin-Opener-Policy: Isolates browsing context
			// same-origin prevents window.opener attacks
			w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")

			next.ServeHTTP(w, r)
		})
	}
}
