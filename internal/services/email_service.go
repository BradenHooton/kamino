package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
)

// EmailService defines the interface for sending emails
type EmailService interface {
	SendVerificationEmail(ctx context.Context, email, token string, expiresAt time.Time) error
}

// AWSSESEmailService sends emails using AWS SES
type AWSSESEmailService struct {
	sesClient   *ses.Client
	fromAddress string
	baseURL     string
	logger      *slog.Logger
}

// NewAWSSESEmailService creates a new AWS SES email service
func NewAWSSESEmailService(region, fromAddress, baseURL string, logger *slog.Logger) (*AWSSESEmailService, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AWSSESEmailService{
		sesClient:   ses.NewFromConfig(cfg),
		fromAddress: fromAddress,
		baseURL:     baseURL,
		logger:      logger,
	}, nil
}

// SendVerificationEmail sends a verification email to the user
func (s *AWSSESEmailService) SendVerificationEmail(ctx context.Context, email, token string, expiresAt time.Time) error {
	// Construct verification link
	verificationLink := fmt.Sprintf("%s/verify-email?token=%s", s.baseURL, token)

	// Create HTML email body
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 4px; }
        .content { padding: 20px 0; }
        .button { display: inline-block; background-color: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { color: #666; font-size: 12px; margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; }
        .warning { background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Verify Your Email Address</h1>
        </div>
        <div class="content">
            <p>Welcome!</p>
            <p>Thank you for creating an account. To complete your registration, please verify your email address by clicking the link below:</p>
            <p><a href="%s" class="button">Verify Email Address</a></p>
            <p>Or copy and paste this link in your browser:<br>
            <code>%s</code></p>
            <div class="warning">
                <strong>⚠️ Security Notice:</strong> This link will expire in 24 hours.
            </div>
            <p><strong>Didn't create this account?</strong><br>
            If you didn't sign up for this account, you can ignore this email. Your email address will not be verified.</p>
        </div>
        <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>If you have any questions, please contact our support team.</p>
        </div>
    </div>
</body>
</html>
`, verificationLink, verificationLink)

	// Create plain text email body
	textBody := fmt.Sprintf(`Verify Your Email Address

Welcome! Thank you for creating an account. To complete your registration, please verify your email address by clicking the link below:

%s

Or copy and paste this link in your browser:
%s

⚠️  Security Notice: This link will expire in 24 hours.

Didn't create this account?
If you didn't sign up for this account, you can ignore this email. Your email address will not be verified.

This is an automated message. Please do not reply to this email.
If you have any questions, please contact our support team.
`, verificationLink, verificationLink)

	// Send email via SES
	input := &ses.SendEmailInput{
		Source: aws.String(s.fromAddress),
		Destination: &types.Destination{
			ToAddresses: []string{email},
		},
		Message: &types.Message{
			Subject: &types.Content{
				Data: aws.String("Verify your email address"),
			},
			Body: &types.Body{
				Html: &types.Content{
					Data: aws.String(htmlBody),
				},
				Text: &types.Content{
					Data: aws.String(textBody),
				},
			},
		},
	}

	result, err := s.sesClient.SendEmail(ctx, input)
	if err != nil {
		s.logger.Error("failed to send verification email via SES",
			slog.String("email", email),
			slog.Any("error", err))
		return fmt.Errorf("failed to send email: %w", err)
	}

	s.logger.Info("verification email sent",
		slog.String("email", email),
		slog.String("message_id", *result.MessageId))

	return nil
}
