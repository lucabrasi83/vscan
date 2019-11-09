package postgresdb

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v4"
	"github.com/lucabrasi83/vscan/logging"
)

type VulscanoDBUser struct {
	UserID       string `json:"userID" example:"1bf3f4e6-5da2-4f82-87e4-606d5bf05d38"`
	Email        string `json:"email" example:"john@vscan.com"`
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	MiddleName   string `json:"middleName"`
	Role         string `json:"role" example:"vulscanouser"`
	EnterpriseID string `json:"enterpriseID" example:"TCL"`
}

func (p *vulscanoDB) FetchUser(u string) (*VulscanoDBUser, error) {

	var user VulscanoDBUser

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `SELECT user_id, email, enterprise_id, role, first_name, last_name, COALESCE(middle_name, '')
				      FROM vulscano_users WHERE 
                      email = $1
					 `

	defer cancelQuery()

	row := p.db.QueryRow(ctxTimeout, sqlQuery, u)

	err := row.Scan(
		&user.UserID,
		&user.Email,
		&user.EnterpriseID,
		&user.Role,
		&user.FirstName,
		&user.LastName,
		&user.MiddleName)

	switch err {
	case pgx.ErrNoRows:
		logging.VSCANLog("error", "not able to find user %v requested in DB", u)
		return nil, fmt.Errorf("not able to find user %v requested in DB", u)

	case nil:
		return &user, nil

	default:
		logging.VSCANLog("error", "error while trying to retrieve user from DB: %v", err)
		return nil, err
	}
}

func (p *vulscanoDB) InsertNewUser(email, pass, ent, role, first, last, middle string) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `INSERT INTO vulscano_users
					  (email, password, enterprise_id, role, first_name, last_name, middle_name)
					  VALUES ($1, crypt($2, gen_salt('bf',8)), $3, $4, $5, $6, $7)
					 `

	defer cancelQuery()

	cTag, err := p.db.Exec(ctxTimeout, sqlQuery, email, pass, ent, role, first, last, middle)

	if err != nil {
		logging.VSCANLog("error",
			"failed to insert user %v with error %v", email, err)

		if strings.Contains(err.Error(), "23505") {
			return fmt.Errorf("user with email %v already exists", email)
		}
		if strings.Contains(err.Error(), "23503") {
			return fmt.Errorf("enterprise ID %v does not exist", ent)
		}
		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VSCANLog("error", "failed to insert user %v", email)
		return fmt.Errorf("failed to insert user %v", email)
	}

	return nil
}
func (p *vulscanoDB) DeleteUser(email []string) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `DELETE FROM vulscano_users
					  WHERE email = $1
					 `

	defer cancelQuery()

	b := &pgx.Batch{}

	for _, e := range email {
		b.Queue(sqlQuery, e)
	}

	// Send Batch SQL Query
	r := p.db.SendBatch(ctxTimeout, b)

	// Close Batch at the end of function
	defer func() {
		errCloseBatch := r.Close()
		if errCloseBatch != nil {
			logging.VSCANLog("error", "Failed to close SQL Batch Job query %v with error %v", sqlQuery, errCloseBatch)
		}
	}()

	c, errSendBatch := r.Exec()

	if errSendBatch != nil {
		logging.VSCANLog(
			"error",
			"Failed to send Batch query %v with error %v", sqlQuery, errSendBatch)

		return errSendBatch

	}

	if c.RowsAffected() < 1 {
		return fmt.Errorf("no deletion of row while executing query %v", sqlQuery)
	}

	return nil
}
func (p *vulscanoDB) PatchUser(email, role, pass, ent, first, last, middle string) error {

	// Set parameters values to NULL if empty
	pRole := normalizeString(role)
	pEnterprise := normalizeString(ent)
	pPassword := normalizeString(pass)
	pFirstName := normalizeString(first)
	pLastName := normalizeString(last)
	pMiddleName := normalizeString(middle)

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `UPDATE vulscano_users SET
			          password = COALESCE(crypt($1, gen_salt('bf', 8)), password),
				      enterprise_id = COALESCE($2, enterprise_id),
					  role = COALESCE($3, role),
					  first_name = COALESCE($5, first_name),
  				      last_name = COALESCE($6, last_name),
                      middle_name = COALESCE($7, middle_name)
					  WHERE email = $4
					 `

	defer cancelQuery()

	cTag, err := p.db.Exec(ctxTimeout, sqlQuery,
		pPassword,
		pEnterprise,
		pRole,
		email,
		pFirstName,
		pLastName,
		pMiddleName,
	)

	if err != nil {
		logging.VSCANLog("error",
			"failed to update user %v with error %v", email, err)

		return err
	}

	if cTag.RowsAffected() == 0 {
		logging.VSCANLog("error",
			"failed to update user %v", email)
		return fmt.Errorf("failed to update user %v", email)
	}

	return nil
}

func (p *vulscanoDB) FetchAllUsers() ([]VulscanoDBUser, error) {

	vulscanoUsers := make([]VulscanoDBUser, 0)

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT user_id, email, enterprise_id, role, first_name, last_name, COALESCE(middle_name, '')
				      FROM vulscano_users`

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery)

	if err != nil {
		logging.VSCANLog("error",
			"cannot fetch Users from DB %v", err.Error(),
		)
		return nil, err
	}

	defer rows.Close()
	for rows.Next() {
		user := VulscanoDBUser{}
		err = rows.Scan(
			&user.UserID,
			&user.Email,
			&user.EnterpriseID,
			&user.Role,
			&user.FirstName,
			&user.LastName,
			&user.MiddleName)

		if err != nil {
			logging.VSCANLog("error",
				"error while scanning vulscano_users table rows %v", err)
			return nil, err
		}
		vulscanoUsers = append(vulscanoUsers, user)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while iterating through vulscano_users table %v", err)
		return nil, err
	}

	return vulscanoUsers, nil

}

func (p *vulscanoDB) AuthenticateUser(user string, pass string) (*VulscanoDBUser, error) {

	var uDB VulscanoDBUser

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `SELECT user_id, email, enterprise_id, role 
				      FROM vulscano_users WHERE 
                      email = $1 AND
                      password = crypt($2, password)
					 `

	defer cancelQuery()

	row := p.db.QueryRow(ctxTimeout, sqlQuery, user, pass)

	err := row.Scan(
		&uDB.UserID,
		&uDB.Email,
		&uDB.EnterpriseID,
		&uDB.Role,
	)

	switch err {
	case pgx.ErrNoRows:
		logging.VSCANLog(
			"error",
			"Authentication Failed for user %v", user)

		return nil, fmt.Errorf("authentication failed for user %v", user)

	case nil:

		return &uDB, nil

	default:
		logging.VSCANLog(
			"error", "error while authenticating user: %v error: %v", user, err)

		return nil, fmt.Errorf("authentication failed for user %v", user)
	}

}

func (p *vulscanoDB) AssertUserExists(id interface{}) bool {

	var u string

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `SELECT user_id
				      FROM vulscano_users WHERE 
                      email = $1
					 `

	defer cancelQuery()

	row := p.db.QueryRow(ctxTimeout, sqlQuery, id)

	err := row.Scan(&u)

	switch err {
	case pgx.ErrNoRows:
		logging.VSCANLog(
			"error", "User %v tried to access but doesn't exist in database", id)
		return false

	case nil:

		return true

	default:
		logging.VSCANLog(
			"error", "Error while asserting user exists in Database: %v", err)

		return false
	}

}
