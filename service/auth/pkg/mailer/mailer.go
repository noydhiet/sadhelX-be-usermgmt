package mailer

import (
	"bytes"
	"fmt"
	"net/smtp"
	"text/template"
)

// type Mail interface {
// 	NewRequest(from, subject, body string, to ...string) *Request
// 	CreateMail(mailReq *Mail) []byte
// 	SendMail(mailReq *Mail) error
// 	// NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail
// }

// type Mail struct {
// 	from    string
// 	to      []string
// 	subject string
// 	body    string
// }

type Config struct {
	identity string
	username string
	password string
	hostAddr string
	hostPort int
}

const (
	mime = "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
)

func NewConfig(identity, username, password, hostAddr string, hostPort int) *Config {
	return &Config{
		identity: identity,
		username: username,
		password: password,
		hostAddr: hostAddr,
		hostPort: hostPort,
	}
}

func NewRequest(from, subject, body string, to ...string) *Mail {
	return &Mail{
		from:    from,
		to:      to,
		subject: subject,
		body:    body,
	}
}

func (req *Mail) SendEmailWithConfig(conf *Config) (bool, error) {

	auth := smtp.PlainAuth(
		conf.identity,
		conf.username,
		conf.password,
		conf.hostAddr,
	)

	msg := "To: " + req.to[0] + "\r\nSubject: " + req.subject + "\r\n" + mime + "\r\n" + req.body

	if err := smtp.SendMail(
		fmt.Sprintf("%s:%d", conf.hostAddr, conf.hostPort),
		auth,
		req.from,
		req.to,
		[]byte(msg),
	); err != nil {
		return false, err
	}

	return true, nil
}

func (req *Mail) WithTemplate(filename string, datastruct interface{}) error {
	t := template.New(filename)
	t, err := template.ParseFiles(filename)
	if err != nil {
		return err
	}
	buff := new(bytes.Buffer)
	if err = t.Execute(buff, datastruct); err != nil {
		return err
	}
	req.body = buff.String()
	return nil
}
