package auth

import (
	"net/http"
	"time"
)

// CookieConfig holds cookie configuration settings
type CookieConfig struct {
	Domain   string // Empty string = current host only
	Secure   bool   // HTTPS only
	SameSite string // "strict", "lax", or "none"
}

// SetRefreshTokenCookie sets a refresh token in an httpOnly cookie
func SetRefreshTokenCookie(w http.ResponseWriter, refreshToken string, maxAge int, config CookieConfig) {
	cookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		Domain:   config.Domain,
		Expires:  time.Now().Add(time.Duration(maxAge) * time.Second),
		MaxAge:   maxAge,
		HttpOnly: true, // Critical: prevents JavaScript access (XSS protection)
		Secure:   config.Secure,
		SameSite: parseSameSite(config.SameSite),
	}
	http.SetCookie(w, cookie)
}

// SetCSRFTokenCookie sets a CSRF token in a readable cookie (not httpOnly)
// JavaScript needs to read this and send it in X-CSRF-Token header
func SetCSRFTokenCookie(w http.ResponseWriter, csrfToken string, maxAge int, config CookieConfig) {
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		Domain:   config.Domain,
		Expires:  time.Now().Add(time.Duration(maxAge) * time.Second),
		MaxAge:   maxAge,
		HttpOnly: false, // Allow JavaScript to read for X-CSRF-Token header
		Secure:   config.Secure,
		SameSite: parseSameSite(config.SameSite),
	}
	http.SetCookie(w, cookie)
}

// ClearRefreshTokenCookie clears the refresh token cookie
func ClearRefreshTokenCookie(w http.ResponseWriter, config CookieConfig) {
	cookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		Domain:   config.Domain,
		MaxAge:   -1, // Negative MaxAge deletes the cookie
		HttpOnly: true,
		Secure:   config.Secure,
		SameSite: parseSameSite(config.SameSite),
	}
	http.SetCookie(w, cookie)
}

// ClearCSRFTokenCookie clears the CSRF token cookie
func ClearCSRFTokenCookie(w http.ResponseWriter, config CookieConfig) {
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		Domain:   config.Domain,
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   config.Secure,
		SameSite: parseSameSite(config.SameSite),
	}
	http.SetCookie(w, cookie)
}

// GetRefreshTokenCookie retrieves the refresh token from cookies
func GetRefreshTokenCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// GetCSRFTokenCookie retrieves the CSRF token from cookies
func GetCSRFTokenCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// parseSameSite converts string to http.SameSite constant
func parseSameSite(sameSite string) http.SameSite {
	switch sameSite {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}
