package repository

import (
	"context"
	"database/sql"
	"shadelx-be-usermgmt/datastruct"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

const (
	queryInsertUser       = "INSERT INTO tbl_mstr_user(user_id, username, email, firstname, lastname, phonenumber, password, created_date, created_by, updated_date, updated_by, token_hash) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);"
	queryGetUserByEmail   = "SELECT * FROM tbl_mstr_user WHERE email=$1 LIMIT 1;"
	queryUsernameIsExists = "SELECT EXISTS(SELECT 1 FROM tbl_mstr_user WHERE username=$1);"
	queryEmailIsExists    = "SELECT EXISTS(SELECT 1 FROM tbl_mstr_user WHERE email=$1);"
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
		return err
	}
	return nil
}

// UsernameIsExist ...
func (repo *PostgresRepository) UsernameIsExist(ctx context.Context, username string) bool {
	var exists bool
	if err := repo.db.QueryRow(queryUsernameIsExists, username).Scan(&exists); err != nil {
		level.Error(repo.logger).Log("err", err)
		return false
	}
	return exists
}

// EmailIsExist ...
func (repo *PostgresRepository) EmailIsExist(ctx context.Context, email string) bool {
	var exists bool
	if err := repo.db.QueryRow(queryEmailIsExists, email).Scan(&exists); err != nil {
		level.Error(repo.logger).Log("err", err)
		return false
	}
	return exists
}
