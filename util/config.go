package util

import (
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/lib/pq"
	"github.com/spf13/viper"
)

// Configurations wraps all the config variables required by the auth service
type Configurations struct {
	ServerAddress string
	DBHost        string
	DBName        string
	DBUser        string
	DBPass        string
	DBPort        string
	DBConn        string
	// AccessTokenPrivateKeyPath  string
	// AccessTokenPublicKeyPath   string
	// RefreshTokenPrivateKeyPath string
	// RefreshTokenPublicKeyPath  string
	JwtSecret               string
	JwtExpiration           int // in minutes
	SendGridAPIKey          string
	MailVerifCodeExpiration int // in hours
	PassResetCodeExpiration int // in minutes
	MailVerifTemplateID     string
	PassResetTemplateID     string
}

// NewConfigurations returns a new Configuration object
func NewConfigurations(logger log.Logger) *Configurations {

	viper.AutomaticEnv()

	dbURL := viper.GetString("DATABASE_URL")
	conn, _ := pq.ParseURL(dbURL)
	level.Debug(logger).Log("msg", "found database url in env, connection string is formed by parsing it")
	level.Debug(logger).Log("db connection string", conn)

	viper.SetDefault("SERVER_ADDRESS", "0.0.0.0:9090")
	viper.SetDefault("DB_HOST", "localhost")
	viper.SetDefault("DB_NAME", "bookite")
	viper.SetDefault("DB_USER", "vignesh")
	viper.SetDefault("DB_PASSWORD", "password")
	viper.SetDefault("DB_PORT", "5432")
	// viper.SetDefault("ACCESS_TOKEN_PRIVATE_KEY_PATH", "./access-private.pem")
	// viper.SetDefault("ACCESS_TOKEN_PUBLIC_KEY_PATH", "./access-public.pem")
	// viper.SetDefault("REFRESH_TOKEN_PRIVATE_KEY_PATH", "./refresh-private.pem")
	// viper.SetDefault("REFRESH_TOKEN_PUBLIC_KEY_PATH", "./refresh-public.pem")
	viper.SetDefault("JWT_SECRET", "bE8fsjU^BD$n%7")
	viper.SetDefault("JWT_EXPIRATION", 30)
	viper.SetDefault("MAIL_VERIFICATION_CODE_EXPIRATION", 24)
	viper.SetDefault("PASSWORD_RESET_CODE_EXPIRATION", 30)
	viper.SetDefault("MAIL_VERIFICATION_TEMPLATE_ID", "d-5ecbea6e38764af3b703daf03f139b48")
	viper.SetDefault("PASSWORD_RESET_TEMPLATE_ID", "d-3fc222d11809441abaa8ed459bb44319")

	configs := &Configurations{
		ServerAddress: viper.GetString("SERVER_ADDRESS"),
		DBHost:        viper.GetString("DB_HOST"),
		DBName:        viper.GetString("DB_NAME"),
		DBUser:        viper.GetString("DB_USER"),
		DBPass:        viper.GetString("DB_PASSWORD"),
		DBPort:        viper.GetString("DB_PORT"),
		DBConn:        conn,
		JwtSecret:     viper.GetString("JWT_SECRET"),
		JwtExpiration: viper.GetInt("JWT_EXPIRATION"),
		// AccessTokenPrivateKeyPath:  viper.GetString("ACCESS_TOKEN_PRIVATE_KEY_PATH"),
		// AccessTokenPublicKeyPath:   viper.GetString("ACCESS_TOKEN_PUBLIC_KEY_PATH"),
		// RefreshTokenPrivateKeyPath: viper.GetString("REFRESH_TOKEN_PRIVATE_KEY_PATH"),
		// RefreshTokenPublicKeyPath:  viper.GetString("REFRESH_TOKEN_PUBLIC_KEY_PATH"),
		SendGridAPIKey:          viper.GetString("SENDGRID_API_KEY"),
		MailVerifCodeExpiration: viper.GetInt("MAIL_VERIFICATION_CODE_EXPIRATION"),
		PassResetCodeExpiration: viper.GetInt("PASSWORD_RESET_CODE_EXPIRATION"),
		MailVerifTemplateID:     viper.GetString("MAIL_VERIFICATION_TEMPLATE_ID"),
		PassResetTemplateID:     viper.GetString("PASSWORD_RESET_TEMPLATE_ID"),
	}

	// reading heroku provided port to handle deployment with heroku
	port := viper.GetString("PORT")
	if port != "" {
		level.Debug(logger).Log("using the port allocated by heroku", port)
		configs.ServerAddress = "0.0.0.0:" + port
	}

	level.Debug(logger).Log("serve port", configs.ServerAddress)
	level.Debug(logger).Log("db host", configs.DBHost)
	level.Debug(logger).Log("db name", configs.DBName)
	level.Debug(logger).Log("db port", configs.DBPort)
	level.Debug(logger).Log("jwt expiration", configs.JwtExpiration)

	return configs
}
