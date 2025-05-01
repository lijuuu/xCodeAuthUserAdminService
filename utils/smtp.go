package utils

import (
	"errors"
	"fmt"
	"strings"

	"xcode/configs"

	"github.com/resend/resend-go/v2"
)

type EmailConfig struct {
	From   string
	ApiKey string
}

func NewEmailConfig() *EmailConfig {
	return &EmailConfig{
		From:   "zenxbattle <noreply@zenxbattle.space>",
		ApiKey: configs.LoadConfig().ResendAPIKey,
	}
}

// Shared HTML template header and footer for consistent styling
func getEmailHeader() string {
	return `
		<!DOCTYPE html>
		<html>
		<head>
			<style>
				body {
					background-color: #1a1a1a;
					color: #ffffff;
					font-family: 'Arial', sans-serif;
					line-height: 1.6;
					margin: 0;
					padding: 0;
				}
				.container {
					max-width: 600px;
					margin: 30px auto;
					background: linear-gradient(135deg, #2a2a2a 0%, #1a1a1a 100%);
					border-radius: 12px;
					box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5);
					padding: 40px;
					text-align: center;
				}
				h1 {
					color: #ffffff;
					font-size: 28px;
					margin-bottom: 20px;
					text-transform: uppercase;
					letter-spacing: 1px;
				}
				p {
					color: #d1d1d1;
					font-size: 16px;
					margin: 10px 0;
				}
				.button {
					display: inline-block;
					padding: 12px 30px;
					background: #4CAF50;
					color: #ffffff !important;
					text-decoration: none;
					border-radius: 25px;
					font-size: 16px;
					font-weight: bold;
					margin: 20px 0;
					transition: background 0.3s ease;
				}
				.button:hover {
					background: #45a049;
				}
				.link {
					color: #4CAF50;
					text-decoration: none;
					word-break: break-all;
				}
				.link:hover {
					text-decoration: underline;
				}
				.footer {
					margin-top: 30px;
					color: #888888;
					font-size: 14px;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<h1>zenxbattle</h1>
	`
}

func getEmailFooter() string {
	return `
				<div class="footer">
					<p>&copy; 2025 zenxbattle. All rights reserved.</p>
					<p>If you did not request this email, please ignore it.</p>
				</div>
			</div>
		</body>
		</html>
	`
}

func SendOTPEmail(to, role, otp string, expiryTime uint64) error {
	config := NewEmailConfig()
	if config.ApiKey == "" {
		return errors.New("resend API key is not set in config")
	}

	client := resend.NewClient(config.ApiKey)

	frontendURL := strings.TrimSuffix(configs.LoadConfig().FRONTENDURL, "/")
	verificationURL := fmt.Sprintf("%s/verify-email?email=%s&token=%s", frontendURL, to, otp)

	htmlContent := getEmailHeader() + fmt.Sprintf(`
				<p>Please verify your email address to continue.</p>
				<p>Your OTP is: <strong>%s</strong> (expires in %d minutes)</p>
				<a href="%s" class="button">Verify Email</a>
				<p>If the button doesn't work, copy and paste this link:</p>
				<p><a href="%s" class="link">%s</a></p>
	`, otp, expiryTime, verificationURL, verificationURL, verificationURL) + getEmailFooter()

	email := &resend.SendEmailRequest{
		From:    config.From,
		To:      []string{to},
		Subject: "zenxbattle Email Verification",
		Html:    htmlContent,
	}

	sent, err := client.Emails.Send(email)
	if err != nil {
		return fmt.Errorf("failed to send OTP email: %v", err)
	}
	fmt.Println("OTP Email sent with ID:", sent.Id)
	return nil
}

func SendForgotPasswordEmail(to, resetLink string) error {
	config := NewEmailConfig()
	if config.ApiKey == "" {
		return errors.New("resend API key is not set in config")
	}

	client := resend.NewClient(config.ApiKey)

	htmlContent := getEmailHeader() + fmt.Sprintf(`
				<p>We received a request to reset your password.</p>
				<p>Click the button below to reset your password:</p>
				<a href="%s" class="button">Reset Password</a>
				<p>This link expires in 1 hour.</p>
				<p>If the button doesn't work, copy and paste this link:</p>
				<p><a href="%s" class="link">%s</a></p>
	`, resetLink, resetLink, resetLink) + getEmailFooter()

	email := &resend.SendEmailRequest{
		From:    config.From,
		To:      []string{to},
		Subject: "zenxbattle Password Reset Request",
		Html:    htmlContent,
	}

	sent, err := client.Emails.Send(email)
	if err != nil {
		return fmt.Errorf("failed to send reset email: %v", err)
	}
	fmt.Println("Reset Email sent with ID:", sent.Id)
	return nil
}

func SendVerificationSuccessEmail(to string) error {
	config := NewEmailConfig()
	if config.ApiKey == "" {
		return errors.New("resend API key is not set in config")
	}

	client := resend.NewClient(config.ApiKey)

	frontendURL := strings.TrimSuffix(configs.LoadConfig().FRONTENDURL, "/")
	dashboardURL := fmt.Sprintf("%s/dashboard", frontendURL)

	htmlContent := getEmailHeader() + fmt.Sprintf(`
				<p>Congratulations! Your email has been successfully verified.</p>
				<p>You're now ready to start battling on zenxbattle.</p>
				<a href="%s" class="button">Go to Dashboard</a>
				<p>Or copy and paste this link:</p>
				<p><a href="%s" class="link">%s</a></p>
	`, dashboardURL, dashboardURL, dashboardURL) + getEmailFooter()

	email := &resend.SendEmailRequest{
		From:    config.From,
		To:      []string{to},
		Subject: "zenxbattle Email Verification Successful",
		Html:    htmlContent,
	}

	sent, err := client.Emails.Send(email)
	if err != nil {
		return fmt.Errorf("failed to send verification success email: %v", err)
	}
	fmt.Println("Verification Success Email sent with ID:", sent.Id)
	return nil
}