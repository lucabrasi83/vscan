package postgresdb

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v4"
	"github.com/lucabrasi83/vulscano/logging"
)

type EnterpriseDB struct {
	EnterpriseID   string `json:"enterpriseID"`
	EnterpriseName string `json:"enterpriseName"`
}

func (p *vulscanoDB) FetchAllEnterprises() ([]EnterpriseDB, error) {

	enterprisesSLice := make([]EnterpriseDB, 0)

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT enterprise_id, enterprise_name
  					  FROM enterprise`

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery)

	if err != nil {
		logging.VulscanoLog("error", "cannot fetch list of enterprises: ", err.Error())
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		ent := EnterpriseDB{}
		err = rows.Scan(
			&ent.EnterpriseID,
			&ent.EnterpriseName,
		)

		if err != nil {
			logging.VulscanoLog("error",
				"error while scanning enterprise table rows: ", err.Error())
			return nil, err
		}
		enterprisesSLice = append(enterprisesSLice, ent)
	}
	err = rows.Err()

	if err != nil {
		logging.VulscanoLog("error",
			"error returned while iterating through enterprise table: ", err.Error())
		return nil, err
	}

	return enterprisesSLice, nil

}

func (p *vulscanoDB) FetchEnterprise(entid string) (*EnterpriseDB, error) {

	var ent EnterpriseDB

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `SELECT enterprise_id, enterprise_name
					  FROM enterprise
					  WHERE enterprise_id = $1
					 `

	defer cancelQuery()

	row := p.db.QueryRow(ctxTimeout, sqlQuery, entid)

	err := row.Scan(
		&ent.EnterpriseID,
		&ent.EnterpriseName,
	)
	switch err {
	case pgx.ErrNoRows:
		logging.VulscanoLog(
			"error", "Enterprise ID "+entid+" not found in database")
		return nil, fmt.Errorf("SSH Gateway %v not found", entid)

	case nil:

		return &ent, nil

	default:
		logging.VulscanoLog(
			"error", "error while searching for enterprise in Database: ", err.Error())

		return nil, fmt.Errorf("error while searching for enterprise %v: %v", entid, err.Error())
	}

}

func (p *vulscanoDB) InsertNewEnterprise(newEnt map[string]string) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `INSERT INTO enterprise (enterprise_id, 					  enterprise_name) 
					  VALUES ($1, $2)
					 `

	defer cancelQuery()

	cTag, err := p.db.Exec(ctxTimeout, sqlQuery, newEnt["entID"], newEnt["entName"])

	if err != nil {
		logging.VulscanoLog("error",
			"failed to insert enterprise: ", newEnt["entID"], " ", err.Error())

		if strings.Contains(err.Error(), "23505") {
			return fmt.Errorf("enterprise ID %v already exists", newEnt["entID"])
		}

		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VulscanoLog("error",
			"failed to insert enterprise: ", newEnt["entID"])
		return fmt.Errorf("failed to insert enterprise %v", newEnt["entID"])
	}

	return nil
}

func (p *vulscanoDB) DeleteEnterprise(entid string) error {

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `DELETE
					  FROM enterprise
					  WHERE enterprise_id = $1
					 `

	defer cancelQuery()

	cTag, err := p.db.Exec(ctxTimeout, sqlQuery, entid)

	if err != nil {
		logging.VulscanoLog("error",
			"failed to delete enterprise: ", entid, " ", err.Error())

		if strings.Contains(err.Error(), "23503") {
			return fmt.Errorf("enterprise ID %v still has devices associated with it. ",
				entid)
		}

		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VulscanoLog("error",
			"failed to delete enterprise: ", entid)
		return fmt.Errorf("failed to delete user %v", entid)
	}

	return nil

}
