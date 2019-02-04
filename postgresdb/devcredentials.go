package postgresdb

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx"
	"github.com/lucabrasi83/vulscano/logging"
)

// UserDeviceCredentials struct represents the Device Credentials to connect to a scanned device
type DeviceCredentialsDB struct {
	CredentialsName         string
	CredentialsDeviceVendor string
	Username                string
	Password                string
	IOSEnablePassword       string
	PrivateKey              string
}

func (p *vulscanoDB) FetchDeviceCredentials(uid string, cn string) (*DeviceCredentialsDB, error) {

	var deviceCreds DeviceCredentialsDB

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	const sqlQuery = `SELECT credentials_name,
 				      device_vendor,
	                  device_username,
	                  COALESCE(pgp_sym_decrypt(device_password, $1), ''), 
	                  COALESCE(pgp_sym_decrypt(device_private_key, $1), ''), 
	                  COALESCE(pgp_sym_decrypt(device_ios_enable_pwd, $1), '')
                      FROM device_credentials_set
					  WHERE user_id = $2 AND credentials_name = $3
					 `

	defer cancelQuery()

	row := p.db.QueryRowEx(ctxTimeout, sqlQuery, nil, pgpSymEncryptKey, uid, cn)

	err := row.Scan(
		&deviceCreds.CredentialsName,
		&deviceCreds.CredentialsDeviceVendor,
		&deviceCreds.Username,
		&deviceCreds.Password,
		&deviceCreds.PrivateKey,
		&deviceCreds.IOSEnablePassword,
	)

	switch err {
	case pgx.ErrNoRows:
		logging.VulscanoLog(
			"error", "Device Credentials Name "+cn+" not found in database")
		return nil, fmt.Errorf("device credentials name %v not found", cn)

	case nil:

		return &deviceCreds, nil

	default:
		logging.VulscanoLog(
			"error", "error while searching for Device Credentials in Database: ", err.Error())

		return nil, fmt.Errorf("error while searching for Device Credentials %v: %v", cn, err.Error())
	}

}
