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

func SendOTPEmail(to, role, otp string, expiryTime uint64) error {
	config := NewEmailConfig()
	if config.ApiKey == "" {
		return errors.New("resend API key is not set in config")
	}

	client := resend.NewClient(config.ApiKey)

	frontendURL := strings.TrimSuffix(configs.LoadConfig().FRONTENDURL, "/")
	verificationURL := fmt.Sprintf("%s/verify-email?email=%s&token=%s", frontendURL, to, otp)

	htmlContent := fmt.Sprintf(`
		<h1>zenxbattle Email Verification</h1>
		<p>Please verify your email:</p>
		<p>Your OTP is: <strong>%s</strong> (expires in %d minutes)</p>
		<a href="%s" style="padding:12px 20px; background:#4CAF50; color:white; text-decoration:none;">Verify Email</a>
		<p>If the button doesn't work, use this link:</p>
		<p><a href="%s">%s</a></p>
	`, otp, expiryTime, verificationURL, verificationURL, verificationURL)
	
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

	htmlContent := fmt.Sprintf(`
		<h1>zenxbattle Password Reset</h1>
		<p>Click below to reset your password:</p>
		<a href="%s" style="padding:12px 20px; background:#4CAF50; color:white; text-decoration:none;">Reset Password</a>
		<p>This link expires in 1 hour.</p>
		<p>If the button doesn't work, copy and paste this link:</p>
		<p><a href="%s">%s</a></p>
	`, resetLink, resetLink, resetLink)

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
