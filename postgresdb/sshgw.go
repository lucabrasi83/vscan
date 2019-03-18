package postgresdb

import (
	"context"
	"fmt"
	"net"

	"github.com/jackc/pgx"
	"github.com/lucabrasi83/vulscano/logging"
)

type SSHGatewayDB struct {
	GatewayName       string
	GatewayIP         net.IP
	GatewayUsername   string
	GatewayPassword   string
	GatewayPrivateKey string
	EnterpriseID      string
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
