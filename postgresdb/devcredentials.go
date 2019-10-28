package postgresdb

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v4"
	"github.com/lucabrasi83/vscan/logging"
)

// UserDeviceCredentials struct represents the Device Credentials to connect to a scanned device
type DeviceCredentialsDB struct {
	CredentialsName         string `json:"credentialsName"`
	CredentialsDeviceVendor string `json:"credentialsDeviceVendor"`
	Username                string `json:"username"`
	Password                string `json:"password"`
	IOSEnablePassword       string `json:"iosEnablePassword"`
	PrivateKey              string `json:"privateKey"`
}

func (p *vulscanoDB) FetchDeviceCredentials(uid string, cn string) (*DeviceCredentialsDB, error) {

	var deviceCreds DeviceCredentialsDB

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

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

	row := p.db.QueryRow(ctxTimeout, sqlQuery, pgpSymEncryptKey, uid, cn)

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
		logging.VSCANLog(
			"error", "Device Credentials Name %v not found in database", cn)
		return nil, fmt.Errorf("device credentials name %v not found", cn)

	case nil:

		return &deviceCreds, nil

	default:
		logging.VSCANLog(
			"error", "error while searching for Device Credentials in Database %v", err)

		return nil, fmt.Errorf("error while searching for Device Credentials %v: %v", cn, err)
	}

}

func (p *vulscanoDB) FetchAllUserDeviceCredentials(uid string) ([]DeviceCredentialsDB, error) {

	var deviceCredentials []DeviceCredentialsDB

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT credentials_name,
 				      device_vendor,
	                  device_username,
	                  COALESCE(pgp_sym_decrypt(device_password, $1), ''), 
	                  COALESCE(pgp_sym_decrypt(device_private_key, $1), ''), 
	                  COALESCE(pgp_sym_decrypt(device_ios_enable_pwd, $1), '')
                      FROM device_credentials_set
					  WHERE user_id = $2`

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, pgpSymEncryptKey, uid)

	if err != nil {
		logging.VSCANLog("error", "cannot fetch user device credentials from DB %v", err)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		devCred := DeviceCredentialsDB{}
		err = rows.Scan(&devCred.CredentialsName,
			&devCred.CredentialsDeviceVendor,
			&devCred.Username,
			&devCred.Password,
			&devCred.PrivateKey,
			&devCred.IOSEnablePassword,
		)

		if err != nil {
			logging.VSCANLog("error",
				"error while scanning device_credentials_set table rows: %v", err)
			return nil, err
		}
		deviceCredentials = append(deviceCredentials, devCred)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while iterating through device_credentials_set table: %v", err)
		return nil, err
	}

	return deviceCredentials, nil

}

func (p *vulscanoDB) DeleteDeviceCredentials(uid string, cn []string) error {

	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `DELETE FROM device_credentials_set
					  WHERE user_id = $1 AND credentials_name = $2`

	defer cancelQuery()

	b := &pgx.Batch{}

	for _, cred := range cn {
		b.Queue(sqlQuery, uid, cred)
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

func (p *vulscanoDB) InsertNewDeviceCredentials(devCredsProps map[string]string) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `INSERT INTO device_credentials_set
			          (credentials_name,
 				      device_vendor,
	                  device_username,
	                  device_password, 
	                  device_private_key,
	                  device_ios_enable_pwd,
					  user_id )
                      VALUES (
						$2, $3, $4, 
						COALESCE(pgp_sym_encrypt($5, $1, 'compress-algo=1, cipher-algo=aes256'),''),
						COALESCE(pgp_sym_encrypt($6, $1, 'compress-algo=1, cipher-algo=aes256'),''),
					    COALESCE(pgp_sym_encrypt($7, $1, 'compress-algo=1, cipher-algo=aes256'),''),
						$8
					   )`

	defer cancelQuery()

	cTag, err := p.db.Exec(
		ctxTimeout,
		sqlQuery,
		pgpSymEncryptKey,
		devCredsProps["credsName"],
		devCredsProps["credsVendor"],
		devCredsProps["credsUsername"],
		devCredsProps["credsPassword"],
		devCredsProps["credsPrivateKey"],
		devCredsProps["credsIOSenable"],
		devCredsProps["credsuserID"],
	)

	if err != nil {
		logging.VSCANLog("error",
			"failed to insert device credentials: %v with error %v", devCredsProps["credsName"], err)

		if strings.Contains(err.Error(), "23505") {
			return fmt.Errorf("device credentials %v already exists", devCredsProps["credsName"])
		}
		if strings.Contains(err.Error(), "23503") {
			return fmt.Errorf("user ID %v does not exist", devCredsProps["credsuserID"])
		}
		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VSCANLog("error",
			"failed to insert device credentials: %v", devCredsProps["credsName"])
		return fmt.Errorf("failed to insert device credentials %v", devCredsProps["credsName"])
	}

	return nil
}

func (p *vulscanoDB) UpdateDeviceCredentials(devCredsProps map[string]string) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `UPDATE device_credentials_set SET
					  credentials_name = COALESCE($9, credentials_name),
				      device_vendor = COALESCE($3, device_vendor),
					  device_username = COALESCE($4, device_username),
					  device_password = COALESCE(pgp_sym_encrypt($5, $1, 'compress-algo=1, cipher-algo=aes256'), device_password),
                      device_private_key = COALESCE(pgp_sym_encrypt($6, $1, 'compress-algo=1, cipher-algo=aes256'),device_private_key),
					  device_ios_enable_pwd = COALESCE(pgp_sym_encrypt($7, $1, 'compress-algo=1,cipher-algo=aes256'),device_ios_enable_pwd)
					  WHERE credentials_name = $2 AND user_id = $8
					`

	defer cancelQuery()

	cTag, err := p.db.Exec(
		ctxTimeout,
		sqlQuery,
		pgpSymEncryptKey,
		devCredsProps["credsCurrentName"],
		devCredsProps["credsVendor"],
		devCredsProps["credsUsername"],
		devCredsProps["credsPassword"],
		devCredsProps["credsPrivateKey"],
		devCredsProps["credsIOSenable"],
		devCredsProps["credsuserID"],
		devCredsProps["credsNewName"],
	)

	if err != nil {
		logging.VSCANLog("error",
			"failed to update device credentials: %v with error %v", devCredsProps["credsName"], err)

		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VSCANLog("error",
			"failed to update device credentials: %v", devCredsProps["credsName"])
		return fmt.Errorf("failed to update device credentials %v", devCredsProps["credsName"])
	}

	return nil
}
