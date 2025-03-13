package utils

import (
	"errors"
	"fmt"
	"net/smtp"
	"strings"

	"xcode/configs"
)

// EmailConfig holds SMTP configuration
type EmailConfig struct {
	From        string
	AppPassword string
	Host        string
	Port        string
}

// NewEmailConfig initializes email configuration from environment variables and app config
func NewEmailConfig() *EmailConfig {
	return &EmailConfig{
		From:        "foodbuddycode@gmail.com",
		AppPassword: configs.LoadConfig().SMTPAppKey,
		Host:        "smtp.gmail.com",
		Port:        "587",
	}
}

// SendOTPEmail sends an OTP email with the OTP embedded in the verification link
func SendOTPEmail(to, role, otp string, expiryTime uint64) error {
	config := NewEmailConfig()
	if config.AppPassword == "" {
		return errors.New("SMTP app password not set in environment variables")
	}

	auth := smtp.PlainAuth("", config.From, config.AppPassword, config.Host)

	// Construct the verification URL with OTP embedded
	frontendURL := strings.TrimSuffix(configs.LoadConfig().FRONTENDURL, "/")
	verificationURL := fmt.Sprintf("%s/verify-email?email=%s&token=%s", frontendURL, to, otp)

	fmt.Println("verificationURL", verificationURL)

	// HTML email content
	htmlContent := fmt.Sprintf(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>FoodBuddy Email Verification</title>
		<style>
			.button {
				background-color: #4CAF50;
				border: none;
				color: white;
				padding: 15px 32px;
				text-align: center;
				text-decoration: none;
				display: inline-block;
				font-size: 16px;
				margin: 4px 2px;
				cursor: pointer;
			}
			.container {
				font-family: Arial, sans-serif;
				max-width: 600px;
				margin: 0 auto;
				padding: 20px;
			}
		</style>
	</head>
	<body>
		<div class="container">
			<h1>FoodBuddy Email Verification</h1>
			<p>Please verify your email address by clicking the button below:</p>
			<p>Your OTP is: <strong>%s</strong> (expires in %d minutes)</p>
			<a href="%s" class="button">Verify Email</a>
			<p>If the button doesn't work, copy and paste this link into your browser:</p>
			<p><a href="%s">%s</a></p>
		</div>
	</body>
	</html>
	`, otp, expiryTime, verificationURL, verificationURL, verificationURL)

	// Email headers and body
	msg := []byte(fmt.Sprintf(
		"To: %s\r\n"+
			"From: %s\r\n"+
			"Subject: FoodBuddy Email Verification\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/html; charset=\"UTF-8\"\r\n"+
			"\r\n"+
			"%s", to, config.From, htmlContent))

	// Send the email
	addr := fmt.Sprintf("%s:%s", config.Host, config.Port)
	err := smtp.SendMail(addr, auth, config.From, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("failed to send OTP email: %v", err)
	}

	return nil
}

// SendForgotPasswordEmail sends a password reset email with the reset token in the link
func SendForgotPasswordEmail(to, resetLink string) error {
	config := NewEmailConfig()
	if config.AppPassword == "" {
		return errors.New("SMTP app password not set in environment variables")
	}

	auth := smtp.PlainAuth("", config.From, config.AppPassword, config.Host)

	// HTML email content
	htmlContent := fmt.Sprintf(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>FoodBuddy Password Reset</title>
		<style>
			.button {
				background-color: #4CAF50;
				border: none;
				color: white;
				padding: 15px 32px;
				text-align: center;
				text-decoration: none;
				display: inline-block;
				font-size: 16px;
				margin: 4px 2px;
				cursor: pointer;
			}
			.container {
				font-family: Arial, sans-serif;
				max-width: 600px;
				margin: 0 auto;
				padding: 20px;
			}
		</style>
	</head>
	<body>
		<div class="container">
			<h1>FoodBuddy Password Reset</h1>
			<p>You requested a password reset. Click the button below to reset your password:</p>
			<a href="%s" class="button">Reset Password</a>
			<p>This link expires in 1 hour.</p>
			<p>If the button doesn't work, copy and paste this link into your browser:</p>
			<p><a href="%s">%s</a></p>
		</div>
	</body>
	</html>
	`, resetLink, resetLink, resetLink)

	// Email headers and body
	msg := []byte(fmt.Sprintf(
		"To: %s\r\n"+
			"From: %s\r\n"+
			"Subject: FoodBuddy Password Reset Request\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/html; charset=\"UTF-8\"\r\n"+
			"\r\n"+
			"%s", to, config.From, htmlContent))

	// Send the email
	addr := fmt.Sprintf("%s:%s", config.Host, config.Port)
	err := smtp.SendMail(addr, auth, config.From, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("failed to send password reset email: %v", err)
	}

	return nil
}