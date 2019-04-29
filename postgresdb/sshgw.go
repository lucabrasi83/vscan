package postgresdb

import (
	"context"
	"fmt"
	"net"

	"github.com/jackc/pgx"
	"github.com/lucabrasi83/vulscano/logging"
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
	                  COALESCE(pgp_sym_decrypt(gateway_private_key, $1), '')
                      FROM ssh_gateway
					  WHERE enterprise_id = $2 AND gateway_name = $3
					 `

	defer cancelQuery()

	row := p.db.QueryRowEx(ctxTimeout, sqlQuery, nil, pgpSymEncryptKey, entid, gw)

	err := row.Scan(
		&sshGw.GatewayName,
		&sshGw.GatewayIP,
		&sshGw.GatewayUsername,
		&sshGw.GatewayPassword,
		&sshGw.GatewayPrivateKey,
	)

	switch err {
	case pgx.ErrNoRows:
		logging.VulscanoLog(
			"error", "SSH Gateway "+gw+" not found in database")
		return nil, fmt.Errorf("SSH Gateway %v not found", gw)

	case nil:

		return &sshGw, nil

	default:
		logging.VulscanoLog(
			"error", "error while searching for SSH Gateway in Database: ", err.Error())

		return nil, fmt.Errorf("error while searching for SSH Gateway %v: %v", gw, err.Error())
	}

}

func (p *vulscanoDB) FetchAllUserSSHGateway(entid string) ([]*SSHGatewayDB, error) {

	var sshGatewaysSlice []*SSHGatewayDB

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT gateway_name, 
	                  gateway_ip, 
	                  gateway_username, 
	                  COALESCE(pgp_sym_decrypt(gateway_password, $1), ''), 
	                  COALESCE(pgp_sym_decrypt(gateway_private_key, $1), '')
                      FROM ssh_gateway
					  WHERE enterprise_id = $2`

	defer cancelQuery()

	rows, err := p.db.QueryEx(ctxTimeout, sqlQuery, nil, pgpSymEncryptKey, entid)

	if err != nil {
		logging.VulscanoLog("error",
			"cannot fetch user SSH gateways from DB: ", err.Error(),
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
		)

		if err != nil {
			logging.VulscanoLog("error",
				"error while scanning ssh_gateway table rows: ", err.Error())
			return nil, err
		}
		sshGatewaysSlice = append(sshGatewaysSlice, &sshGw)
	}
	err = rows.Err()
	if err != nil {
		logging.VulscanoLog("error",
			"error returned while iterating through ssh_gateway table: ", err.Error())
		return nil, err
	}

	return sshGatewaysSlice, nil

}

func (p *vulscanoDB) DeleteUserSSHGateway(entid string, gw string) error {

	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `DELETE FROM ssh_gateway
					  WHERE enterprise_id = $1 AND gateway_name = $2`

	defer cancelQuery()

	cTag, err := p.db.ExecEx(ctxTimeout, sqlQuery, nil, entid, gw)

	if err != nil {
		logging.VulscanoLog("error",
			"failed to delete SSH gateway: ", gw, " ", err.Error())

		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VulscanoLog("error",
			"failed to delete SSH gateway: ", gw)
		return fmt.Errorf("failed to delete SSH gateway %v", gw)
	}

	return nil
}
