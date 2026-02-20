package integration

import (
	"fmt"
	"time"
)

// TestUser generates unique test user credentials using timestamp
func TestUser(suffix string) (email, password string) {
	ts := time.Now().Unix()
	email = fmt.Sprintf("test-%d-%s@example.com", ts, suffix)
	password = "TestPassword123!"
	return
}

// ExtractTokenFromEmail extracts verification token from email body
// Email format: "Verification token: {token}"
func ExtractTokenFromEmail(emailBody string) string {
	prefix := "Verification token: "
	start := len(prefix)
	if len(emailBody) > start {
		return emailBody[start:]
	}
	return ""
}
