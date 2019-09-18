package postgresdb

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v4"
	"github.com/lucabrasi83/vulscano/logging"
)

type VulscanoDBUser struct {
	UserID       string `json:"userID" example:"1bf3f4e6-5da2-4f82-87e4-606d5bf05d38"`
	Email        string `json:"email" example:"john@vulscano.com"`
	Role         string `json:"role" example:"vulscanouser"`
	EnterpriseID string `json:"enterpriseID" example:"TCL"`
}

func (p *vulscanoDB) FetchUser(u string) (*VulscanoDBUser, error) {

	var user VulscanoDBUser

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `SELECT user_id, email, enterprise_id, role
				      FROM vulscano_users WHERE 
                      email = $1
					 `

	defer cancelQuery()

	row := p.db.QueryRow(ctxTimeout, sqlQuery, u)

	err := row.Scan(&user.UserID, &user.Email, &user.EnterpriseID, &user.Role)

	switch err {
	case pgx.ErrNoRows:
		logging.VulscanoLog("error", "not able to find user requested in DB: ", u)
		return nil, fmt.Errorf("not able to find user %v requested in DB", u)

	case nil:
		return &user, nil

	default:
		logging.VulscanoLog("error", "error while trying to retrieve user from DB: ", err.Error())
		return nil, err
	}
}

func (p *vulscanoDB) InsertNewUser(email string, pass string, ent string, role string) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `INSERT INTO vulscano_users
					  (email, password, enterprise_id, role)
					  VALUES ($1, crypt($2, gen_salt('bf',8)), $3, $4)
					 `

	defer cancelQuery()

	cTag, err := p.db.Exec(ctxTimeout, sqlQuery, email, pass, ent, role)

	if err != nil {
		logging.VulscanoLog("error",
			"failed to insert user: ", email, " ", err.Error())

		if strings.Contains(err.Error(), "23505") {
			return fmt.Errorf("user with email %v already exists", email)
		}
		if strings.Contains(err.Error(), "23503") {
			return fmt.Errorf("enterprise ID %v does not exist", ent)
		}
		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VulscanoLog("error",
			"failed to insert user: ", email)
		return fmt.Errorf("failed to insert user %v", email)
	}

	return nil
}
func (p *vulscanoDB) DeleteUser(email string) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `DELETE FROM vulscano_users
					  WHERE email = $1
					 `

	defer cancelQuery()

	cTag, err := p.db.Exec(ctxTimeout, sqlQuery, email)

	if err != nil {
		logging.VulscanoLog("error",
			"failed to delete user: ", email, " ", err.Error())

		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VulscanoLog("error",
			"failed to delete user: ", email)
		return fmt.Errorf("failed to delete user %v", email)
	}

	return nil
}
func (p *vulscanoDB) PatchUser(email string, role string, pass string, ent string) error {

	// Set parameters values to NULL if empty
	pRole := normalizeString(role)
	pEnterprise := normalizeString(ent)
	pPassword := normalizeString(pass)

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `UPDATE vulscano_users SET
			          password = COALESCE(crypt($1, gen_salt('bf', 8)), password),
				      enterprise_id = COALESCE($2, enterprise_id),
					  role = COALESCE($3, role)
					  WHERE email = $4
					 `

	defer cancelQuery()

	cTag, err := p.db.Exec(ctxTimeout, sqlQuery,
		pPassword,
		pEnterprise,
		pRole,
		email)

	if err != nil {
		logging.VulscanoLog("error",
			"failed to update user: ", email, " ", err.Error())

		return err
	}

	if cTag.RowsAffected() == 0 {
		logging.VulscanoLog("error",
			"failed to update user: ", email)
		return fmt.Errorf("failed to update user %v", email)
	}

	return nil
}

func (p *vulscanoDB) FetchAllUsers() ([]VulscanoDBUser, error) {

	vulscanoUsers := make([]VulscanoDBUser, 0)

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT user_id, email, enterprise_id, role FROM vulscano_users`

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery)

	if err != nil {
		logging.VulscanoLog("error",
			"cannot fetch Users from DB: ", err.Error(),
		)
		return nil, err
	}

	defer rows.Close()
	for rows.Next() {
		user := VulscanoDBUser{}
		err = rows.Scan(&user.UserID, &user.Email, &user.EnterpriseID, &user.Role)

		if err != nil {
			logging.VulscanoLog("error",
				"error while scanning vulscano_users table rows: ", err.Error())
			return nil, err
		}
		vulscanoUsers = append(vulscanoUsers, user)
	}
	err = rows.Err()
	if err != nil {
		logging.VulscanoLog("error",
			"error returned while iterating through vulscano_users table: ", err.Error())
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
		logging.VulscanoLog(
			"error",
			"Authentication Failed for user: ", user)

		return nil, fmt.Errorf("authentication failed for user %v", user)

	case nil:

		return &uDB, nil

	default:
		logging.VulscanoLog(
			"error",
			fmt.Sprintf("error while authenticating user: %v error: %v", user, err.Error()))

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
		logging.VulscanoLog(
			"error", "User ", id, " tried to access but doesn't exist in database.")
		return false

	case nil:

		return true

	default:
		logging.VulscanoLog(
			"error", "Error while asserting user exists in Database: ", err.Error())

		return false
	}

}
