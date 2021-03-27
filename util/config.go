package util

import (
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/lib/pq"
	"github.com/spf13/viper"
)

// Configurations wraps all the config variables required by the auth service
type Configurations struct {
	// ServerAddress string
	ServerPort              string
	DBHost                  string
	DBName                  string
	DBUser                  string
	DBPass                  string
	DBPort                  string
	DBConn                  string
	JwtSecret               string
	JwtExpiration           int // in minutes
	PassResetCodeExpiration int // in minutes
	PassResetTemplatePath   string
	PassResetTemplateID     string
	MailVerifCodeExpiration int // in hours
	MailVerifTemplatePath   string
	MailVerifTemplateID     string
}

// NewConfigurations returns a new Configuration object
func NewConfigurations(logger log.Logger) *Configurations {

	viper.AutomaticEnv()

	dbURL := viper.GetString("DATABASE_URL")
	conn, _ := pq.ParseURL(dbURL)
	level.Debug(logger).Log("msg", "found database url in env, connection string is formed by parsing it")
	level.Debug(logger).Log("db connection string", conn)

	// viper.SetDefault("SERVER_ADDRESS", "0.0.0.0:8088")
	viper.SetDefault("SERVER_PORT", "8088")
	viper.SetDefault("DB_HOST", "sadhelx_db")
	// viper.SetDefault("DB_HOST", "localhost")
	viper.SetDefault("DB_NAME", "sdx_usermgmt_db")
	viper.SetDefault("DB_USER", "sadhelx_usr")
	viper.SetDefault("DB_PASSWORD", "s4dhelx")
	viper.SetDefault("DB_PORT", "5432")
	// viper.SetDefault("DB_PORT", "54321")

	viper.SetDefault("JWT_SECRET", "bE8fsjU^BD$n%7")
	viper.SetDefault("JWT_EXPIRATION", 30)
	viper.SetDefault("PASSWORD_RESET_CODE_EXPIRATION", 15)
	viper.SetDefault("PASSWORD_RESET_TEMPLATE_PATH", "templates/password_reset.html")
	viper.SetDefault("MAIL_VERIFICATION_CODE_EXPIRATION", 24)
	viper.SetDefault("MAIL_VERIFICATION_TEMPLATE_PATH", "templates/confirm_mail.html")
	viper.SetDefault("MAIL_VERIF_TEMPLATE_ID", "d-33f5050a59604892b76f37450f476f12")
	viper.SetDefault("PASS_RESET_TEMPLATe_ID", "d-86a003810c6341fd9d4442738e7b95a8")

	configs := &Configurations{
		// ServerAddress: viper.GetString("SERVER_ADDRESS"),
		ServerPort:              viper.GetString("SERVER_PORT"),
		DBHost:                  viper.GetString("DB_HOST"),
		DBName:                  viper.GetString("DB_NAME"),
		DBUser:                  viper.GetString("DB_USER"),
		DBPass:                  viper.GetString("DB_PASSWORD"),
		DBPort:                  viper.GetString("DB_PORT"),
		DBConn:                  conn,
		JwtSecret:               viper.GetString("JWT_SECRET"),
		JwtExpiration:           viper.GetInt("JWT_EXPIRATION"),
		PassResetCodeExpiration: viper.GetInt("PASSWORD_RESET_CODE_EXPIRATION"),
		PassResetTemplatePath:   viper.GetString("PASSWORD_RESET_TEMPLATE_PATH"),
		MailVerifCodeExpiration: viper.GetInt("MAIL_VERIFICATION_CODE_EXPIRATION"),
		MailVerifTemplatePath:   viper.GetString("MAIL_VERIFICATION_TEMPLATE_PATH"),
		MailVerifTemplateID:     viper.GetString("MAIL_VERIF_TEMPLATE_ID"),
		PassResetTemplateID:     viper.GetString("PASS_RESET_TEMPLATe_ID"),
	}

	level.Debug(logger).Log("serve port", configs.ServerPort)
	level.Debug(logger).Log("db host", configs.DBHost)
	level.Debug(logger).Log("db name", configs.DBName)
	level.Debug(logger).Log("db port", configs.DBPort)
	level.Debug(logger).Log("jwt expiration", configs.JwtExpiration)

	return configs
}
