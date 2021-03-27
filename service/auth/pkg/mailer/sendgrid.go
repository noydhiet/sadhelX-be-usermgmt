package mailer

import (
	"fmt"
	"shadelx-be-usermgmt/util"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// MailService represents the interface for our mail service.
type Service interface {
	// CreateMail(mailReq *Mail) []byte
	CreateMail(mailReq *Mail) *mail.SGMailV3

	SendMail(mailReq *Mail) error
	NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail
}

type MailType int

// List of Mail Types we are going to send.
const (
	MailConfirmation MailType = iota + 1
	PassReset
)

// MailData represents the data to be sent to the template of the mail.
type MailData struct {
	Username string
	Code     string
}

// Mail represents a email request
type Mail struct {
	from    string
	to      []string
	subject string
	body    string
	mtype   MailType
	data    *MailData
}

// SGMailService is the sendgrid implementation of our MailService.
type service struct {
	// logger  logrus.Logger
	configs *util.Configurations
}

// NewSGMailService returns a new instance of SGMailService
// func NewSGMailService(logger logrus.Logger, configs *config.Configurations) *SGMailService {
func NewSGMailService(configs *util.Configurations) Service {
	return &service{
		configs: configs,
	}
}

// CreateMail takes in a mail request and constructs a sendgrid mail type.
// func (ms *SGMailService) CreateMail(mailReq *Mail) []byte {
func (ms *service) CreateMail(mailReq *Mail) *mail.SGMailV3 {

	m := mail.NewV3Mail()

	from := mail.NewEmail("SadhelX Support", mailReq.from)

	// m.Subject = mailReq.subject
	m.SetFrom(from)

	if mailReq.mtype == MailConfirmation {
		// fmt.Println("template ", ms.configs.MailVerifTemplateID)
		m.SetTemplateID(ms.configs.MailVerifTemplateID)
		// m.SetTemplateID("d-33f5050a59604892b76f37450f476f12")

	} else if mailReq.mtype == PassReset {
		// fmt.Println("template ", ms.configs.PassResetTemplateID)
		m.SetTemplateID(ms.configs.PassResetTemplateID)
		// m.SetTemplateID("d-33f5050a59604892b76f37450f476f12")
	}

	p := mail.NewPersonalization()

	tos := make([]*mail.Email, 0)
	for _, to := range mailReq.to {
		tos = append(tos, mail.NewEmail("user", to))
	}

	p.AddTos(tos...)

	p.SetDynamicTemplateData("username", mailReq.data.Username)
	p.SetDynamicTemplateData("code", mailReq.data.Code)

	m.AddPersonalizations(p)

	// return mail.GetRequestBody(m)
	return m
}

// SendMail creates a sendgrid mail from the given mail request and sends it.
func (ms *service) SendMail(mailReq *Mail) error {

	msg := ms.CreateMail(mailReq)
	client := sendgrid.NewSendClient("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")
	response, err := client.Send(msg)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(response.StatusCode)
		fmt.Println(response.Body)
		fmt.Println(response.Headers)
	}

	return nil
}

// NewMail returns a new mail request.
func (ms *service) NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail {
	return &Mail{
		from:    from,
		to:      to,
		subject: subject,
		mtype:   mailType,
		data:    data,
	}
}
