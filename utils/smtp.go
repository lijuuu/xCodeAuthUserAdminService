package utils

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"

	configs "xcode/configs"
)

// SendEmail sends an email using SMTP
func SendEmail(config *configs.Config, to string, subject string, body string) error {
	// Configure SMTP auth
	auth := smtp.PlainAuth("", config.SMTPUser, config.SMTPAppKey, config.SMTPHost)

	// Set up the message
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", to, subject, body))

	// Connect to the SMTP server
	hostPort := fmt.Sprintf("%s:%s", config.SMTPHost, config.SMTPPort)
	conn, err := tls.Dial("tcp", hostPort, &tls.Config{
		InsecureSkipVerify: true, // For development; use false in production and set up proper certificates
	})
	if err != nil {
		log.Printf("Failed to connect to SMTP server: %v", err)
		return err
	}

	client, err := smtp.NewClient(conn, config.SMTPHost)
	if err != nil {
		log.Printf("Failed to create SMTP client: %v", err)
		return err
	}
	defer client.Close()

	// Authenticate
	if err = client.Auth(auth); err != nil {
		log.Printf("SMTP authentication failed: %v", err)
		return err
	}

	// Set the sender and recipient
	if err = client.Mail(config.SMTPUser); err != nil {
		return err
	}
	if err = client.Rcpt(to); err != nil {
		return err
	}

	// Send the email
	w, err := client.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}

	return client.Quit()
}