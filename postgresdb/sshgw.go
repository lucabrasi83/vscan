package postgresdb

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/jackc/pgx/v4"
	"github.com/lucabrasi83/vscan/logging"
)

type SSHGatewayDB struct {
	GatewayName       string `json:"gatewayName"`
	GatewayIP         net.IP `json:"gatewayIP"`
	GatewayUsername   string `json:"gatewayUsername"`
	GatewayPassword   string `json:"gatewayPassword"`
	GatewayPrivateKey string `json:"gatewayPrivateKey"`
	EnterpriseID      string `json:"enterpriseID"`
}

func (p *vulscanoDB) FetchUserSSHGateway(entid string, gw string) (*SSHGatewayDB, error) {

	var sshGw SSHGatewayDB

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `SELECT gateway_name, 
	                  gateway_ip, 
	                  gateway_username, 
	                  COALESCE(pgp_sym_decrypt(gateway_password, $1), ''), 
	                  COALESCE(pgp_sym_decrypt(gateway_private_key, $1), ''),
                      enterprise_id
                      FROM ssh_gateway
					  WHERE enterprise_id = $2 AND gateway_name = $3
					 `

	defer cancelQuery()

	row := p.db.QueryRow(ctxTimeout, sqlQuery, pgpSymEncryptKey, entid, gw)

	err := row.Scan(
		&sshGw.GatewayName,
		&sshGw.GatewayIP,
		&sshGw.GatewayUsername,
		&sshGw.GatewayPassword,
		&sshGw.GatewayPrivateKey,
		&sshGw.EnterpriseID,
	)

	switch err {
	case pgx.ErrNoRows:
		logging.VSCANLog(
			"error", "SSH Gateway %v not found in database", gw)
		return nil, fmt.Errorf("SSH Gateway %v not found", gw)

	case nil:

		return &sshGw, nil

	default:
		logging.VSCANLog(
			"error", "error while searching for SSH Gateway %v in Database: %v", gw, err.Error())

		return nil, fmt.Errorf("error while searching for SSH Gateway %v: %v", gw, err.Error())
	}

}

func (p *vulscanoDB) FetchAllUserSSHGateway(entid string) ([]SSHGatewayDB, error) {

	sshGatewaysSlice := make([]SSHGatewayDB, 0)

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT gateway_name, 
	                  gateway_ip, 
	                  gateway_username, 
	                  COALESCE(pgp_sym_decrypt(gateway_password, $1), ''), 
	                  COALESCE(pgp_sym_decrypt(gateway_private_key, $1), ''),
				      enterprise_id
                      FROM ssh_gateway
					  WHERE enterprise_id = $2`

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, pgpSymEncryptKey, entid)

	if err != nil {
		logging.VSCANLog("error",
			"cannot fetch user SSH gateways from DB: %v", err.Error(),
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		sshGw := SSHGatewayDB{}
		err = rows.Scan(
			&sshGw.GatewayName,
			&sshGw.GatewayIP,
			&sshGw.GatewayUsername,
			&sshGw.GatewayPassword,
			&sshGw.GatewayPrivateKey,
			&sshGw.EnterpriseID,
		)

		if err != nil {
			logging.VSCANLog("error",
				"error while scanning ssh_gateway table rows: %v", err.Error())
			return nil, err
		}
		sshGatewaysSlice = append(sshGatewaysSlice, sshGw)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while iterating through ssh_gateway table: %v", err.Error())
		return nil, err
	}

	return sshGatewaysSlice, nil

}

func (p *vulscanoDB) DeleteUserSSHGateway(entid string, gw []string) error {

	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `DELETE FROM ssh_gateway
					  WHERE enterprise_id = $1 AND gateway_name = $2`

	defer cancelQuery()

	b := &pgx.Batch{}

	for _, g := range gw {
		b.Queue(sqlQuery, entid, g)
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

		logging.VSCANLog("warning", "no deletion of row while executing query %v", sqlQuery)
		return fmt.Errorf("no deletion of row while executing query %v", sqlQuery)
	}

	return nil

}

func (p *vulscanoDB) CreateUserSSHGateway(sshgwProps map[string]string) error {
	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `INSERT INTO ssh_gateway
                      (gateway_name, gateway_ip, gateway_username, gateway_password, gateway_private_key, enterprise_id)
			          VALUES($2, $3, $4,
					  COALESCE(pgp_sym_encrypt($5, $1, 'compress-algo=1, cipher-algo=aes256'),''),
				      COALESCE(pgp_sym_encrypt($6, $1, 'compress-algo=1, cipher-algo=aes256'),''),
					  $7)
					`

	defer cancelQuery()

	cTag, err := p.db.Exec(
		ctxTimeout,
		sqlQuery,
		pgpSymEncryptKey,
		sshgwProps["gwName"],
		sshgwProps["gwIP"],
		sshgwProps["gwUsername"],
		sshgwProps["gwPassword"],
		sshgwProps["gwPrivateKey"],
		sshgwProps["gwEnterprise"],
	)

	if err != nil {
		logging.VSCANLog("error",
			"failed to create SSH Gateway: %v with error %v", sshgwProps["gwName"], err)

		if strings.Contains(err.Error(), "23505") {
			return fmt.Errorf("SSH Gateway %v already exists", sshgwProps["gwName"])
		}
		if strings.Contains(err.Error(), "23503") {
			return fmt.Errorf("enterprise ID %v does not exist", sshgwProps["gwEnterprise"])
		}

		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VSCANLog("error",
			"failed to update SSH Gateway: %v", sshgwProps["gwName"])
		return fmt.Errorf("failed to create SSH Gateway %v", sshgwProps["gwName"])
	}

	return nil
}

func (p *vulscanoDB) UpdateUserSSHGateway(sshgwProps map[string]string) error {
	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `UPDATE ssh_gateway SET
					  gateway_ip = COALESCE($3, gateway_ip),
				      gateway_username = COALESCE($4, gateway_username),
					  gateway_password =  COALESCE(pgp_sym_encrypt($5, $1, 'compress-algo=1, cipher-algo=aes256'),gateway_password), 
					  gateway_private_key =  COALESCE(pgp_sym_encrypt($6, $1, 'compress-algo=1, cipher-algo=aes256'),gateway_private_key)
					  WHERE gateway_name = $2 AND enterprise_id = $7
					`

	defer cancelQuery()

	cTag, err := p.db.Exec(
		ctxTimeout,
		sqlQuery,
		pgpSymEncryptKey,
		sshgwProps["gwName"],
		sshgwProps["gwIP"],
		sshgwProps["gwUsername"],
		sshgwProps["gwPassword"],
		sshgwProps["gwPrivateKey"],
		sshgwProps["gwEnterprise"],
	)

	if err != nil {
		logging.VSCANLog("error",
			"failed to update SSH Gateway: %v with error %v", sshgwProps["gwName"], err)

		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VSCANLog("error",
			"failed to update SSH Gateway: %v", sshgwProps["gwName"])
		return fmt.Errorf("failed to update SSH Gateway %v", sshgwProps["gwName"])
	}

	return nil
}
