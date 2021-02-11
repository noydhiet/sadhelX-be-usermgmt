package repository

import (
	"context"
	"database/sql"
	"shadelx-be-usermgmt/datastruct"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

const (
	queryInsertUser             = "INSERT INTO tbl_mstr_user(user_id, username, email, firstname, lastname, phonenumber, password, created_date, created_by, updated_date, updated_by, token_hash) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);"
	queryGetUserByEmail         = "SELECT * FROM tbl_mstr_user WHERE email=$1 LIMIT 1;"
	queryGetUserByUsername      = "SELECT * FROM tbl_mstr_user WHERE username=$1 LIMIT 1;"
	queryUsernameIsExists       = "SELECT EXISTS(SELECT 1 FROM tbl_mstr_user WHERE username=$1);"
	queryEmailIsExists          = "SELECT EXISTS(SELECT 1 FROM tbl_mstr_user WHERE email=$1);"
	queryStoreVerificationData  = "INSERT INTO tbl_trx_verification_email(email, code, type, expires_at) VALUES($1, $2, $3, $4)"
	queryGetVerificationData    = "SELECT * FROM tbl_trx_verification_email WHERE email = $1 AND type = $2"
	queryDeleteVerificationData = "DELETE FROM tbl_trx_verification_email WHERE email = $1 AND type = $2"
)

// PostgresRepository has the implementation of the db methods.
type PostgresRepository struct {
	db     *sql.DB
	logger log.Logger
}

// NewPostgresRepository returns a new PostgresRepository instance
func NewPostgresRepository(db *sql.DB, logger log.Logger) *PostgresRepository {
	return &PostgresRepository{db, log.With(logger, "repo", "postgres")}
}

// GetUserByUsername retrieves the user object having the given usernmae, else returns error
func (repo *PostgresRepository) GetUserByUsername(ctx context.Context, username string) (*datastruct.UserInformation, error) {
	level.Debug(repo.logger).Log("msg", "querying for user with email", "username", username)
	var user datastruct.UserInformation

	err := repo.db.QueryRowContext(ctx, queryGetUserByUsername, username).Scan(
		&user.UserID,
		&user.Username,
		&user.Email,
		&user.Firstname,
		&user.Lastname,
		&user.Phonenumber,
		&user.Password,
		&user.CreatedBy,
		&user.CreatedDate,
		&user.UpdatedBy,
		&user.UpdatedDate,
		&user.TokenHash,
	)
	if err != nil {
		return nil, err
	}
	level.Debug(repo.logger).Log("msg", "read users", "user", user)
	return &user, nil
}

// GetUserByEmail retrieves the user object having the given email, else returns error
func (repo *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*datastruct.UserInformation, error) {
	level.Debug(repo.logger).Log("msg", "querying for user with email", "email", email)
	var user datastruct.UserInformation

	err := repo.db.QueryRowContext(ctx, queryGetUserByEmail, email).Scan(
		&user.UserID,
		&user.Username,
		&user.Email,
		&user.Firstname,
		&user.Lastname,
		&user.Phonenumber,
		&user.Password,
		&user.CreatedBy,
		&user.CreatedDate,
		&user.UpdatedBy,
		&user.UpdatedDate,
		&user.TokenHash,
	)
	if err != nil {
		return nil, err
	}
	level.Debug(repo.logger).Log("msg", "read users", "user", user)
	return &user, nil
}

// Create inserts the given user into the database
func (repo *PostgresRepository) Create(ctx context.Context, user *datastruct.UserInformation) error {

	level.Debug(repo.logger).Log("msg", "creating users", "user", user)
	_, err := repo.db.ExecContext(
		ctx,
		queryInsertUser,
		user.UserID,
		user.Username,
		user.Email,
		user.Firstname,
		user.Lastname,
		user.Phonenumber,
		user.Password,
		user.CreatedDate,
		user.CreatedBy,
		user.UpdatedDate,
		user.UpdatedBy,
		user.TokenHash,
	)
	if err != nil {
		level.Error(repo.logger).Log("err", err)
		return err
	}
	return nil
}

// UsernameIsExist check
func (repo *PostgresRepository) UsernameIsExist(ctx context.Context, username string) bool {
	var exists bool
	if err := repo.db.QueryRow(queryUsernameIsExists, username).Scan(&exists); err != nil {
		level.Error(repo.logger).Log("err", err)
		return false
	}
	return exists
}

// EmailIsExist check
func (repo *PostgresRepository) EmailIsExist(ctx context.Context, email string) bool {
	var exists bool
	if err := repo.db.QueryRow(queryEmailIsExists, email).Scan(&exists); err != nil {
		level.Error(repo.logger).Log("err", err)
		return false
	}
	return exists
}

// StoreVerificationData ...
func (repo *PostgresRepository) StoreVerificationData(ctx context.Context, data *datastruct.VerificationData) error {
	level.Debug(repo.logger).Log("msg", "creating verification data", "data", data)
	_, err := repo.db.ExecContext(
		ctx,
		queryStoreVerificationData,
		data.Email,
		data.Code,
		data.Type,
		data.ExpiresAt,
	)
	if err != nil {
		level.Error(repo.logger).Log("err", err)
		return err
	}
	return nil
}

// GetVerificationData retrieves the stored verification code.
func (repo *PostgresRepository) GetVerificationData(ctx context.Context, email string, verificationDataType int) (*datastruct.VerificationData, error) {

	var verificationData datastruct.VerificationData
	err := repo.db.QueryRowContext(ctx, queryGetVerificationData, email, verificationDataType).Scan(
		&verificationData.Email,
		&verificationData.Code,
		&verificationData.Type,
		&verificationData.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	level.Debug(repo.logger).Log("msg", "read verificationData", "verificationData", verificationData)
	return &verificationData, nil
}

// DeleteVerificationData deletes a used verification data
func (repo *PostgresRepository) DeleteVerificationData(ctx context.Context, verificationData *datastruct.VerificationData) error {

	_, err := repo.db.ExecContext(
		ctx,
		queryDeleteVerificationData,
		verificationData.Email,
		verificationData.Type,
	)
	if err != nil {
		level.Error(repo.logger).Log("err", err)
		return err
	}
	return nil
}

// UpdatePassword updates the user password
func (repo *PostgresRepository) UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error {

	query := "update users set password = $1, tokenhash = $2 where id = $3"
	_, err := repo.db.ExecContext(ctx, query, password, tokenHash, userID)
	return err
}
