package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	pkglogger "github.com/BradenHooton/kamino/pkg/logger"
	"github.com/go-chi/chi/v5/middleware"
)

// SecureLogger returns a middleware for logging HTTP requests with sensitive data redaction
func SecureLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status and size
			wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			// Call next handler
			next.ServeHTTP(wrapped, r)

			// Log request details
			duration := time.Since(start)
			statusCode := wrapped.Status()
			bytesWritten := wrapped.BytesWritten()

			// Extract request ID from context
			requestID := middleware.GetReqID(r.Context())

			// Sanitize query string if it contains sensitive parameters
			path := r.URL.Path
			if pkglogger.SanitizeQueryString(r.URL.RawQuery) {
				path = path + "?[REDACTED]"
			} else if r.URL.RawQuery != "" {
				path = r.URL.Path + "?" + r.URL.RawQuery
			}

			// Log request with sanitized data
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", path),
				slog.Int("status", statusCode),
				slog.Int64("bytes", int64(bytesWritten)),
				slog.String("duration", duration.String()),
				slog.String("request_id", requestID),
				slog.String("remote_addr", r.RemoteAddr),
			}

			logger.LogAttrs(context.Background(), slog.LevelInfo, "http_request", attrs...)
		})
	}
}
