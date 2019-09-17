package postgresdb

import (
	"context"
	"net"
	"time"

	"github.com/lucabrasi83/vulscano/logging"
)

type DeviceVADB struct {
	DeviceID         string    `json:"deviceID"`
	MgmtIPAddress    net.IP    `json:"mgmtIP"`
	LastScan         time.Time `json:"lastScan"`
	EnterpriseID     string    `json:"enterpriseID"`
	ScanMeanTime     int       `json:"scanMeanTimeMilliseconds"`
	OSType           string    `json:"osType"`
	OSVersion        string    `json:"osVersion"`
	DeviceModel      string    `json:"deviceModel"`
	SerialNumber     string    `json:"serialNumber"`
	TotalVulnScanned int       `json:"totalVulnScanned"`
}

func (p *vulscanoDB) FetchAllDevices() ([]DeviceVADB, error) {

	vulscanoDevices := make([]DeviceVADB, 0)

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT device_id, serial_number FROM device_va_results`

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery)

	if err != nil {
		logging.VulscanoLog("error",
			"cannot fetch Devices from DB: ", err.Error(),
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		dev := DeviceVADB{}
		err = rows.Scan(&dev.DeviceID, &dev.SerialNumber)

		if err != nil {
			logging.VulscanoLog("error",
				"error while scanning device_va_results table rows: ", err.Error())
			return nil, err
		}
		vulscanoDevices = append(vulscanoDevices, dev)
	}
	err = rows.Err()
	if err != nil {
		logging.VulscanoLog("error",
			"error returned while iterating through device_va_results table: ", err.Error())
		return nil, err
	}

	return vulscanoDevices, nil

}

func (p *vulscanoDB) AdminGetDevVAResultsBySA(vuln string, ent string) ([]DeviceVADB, error) {

	devSlice := make([]DeviceVADB, 0)

	pEnt := normalizeString(ent)

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT device_id, mgmt_ip_address, last_successful_scan, enterprise_id,
					  scan_mean_time, os_type, os_version, device_model, 
					  serial_number, total_vulnerabilities_scanned
					  FROM device_va_results 
					  WHERE $1 = ANY(vulnerabilities_found)
					  AND (enterprise_id = $2 OR $2 IS NULL)
				     `

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, vuln, pEnt)

	if err != nil {
		logging.VulscanoLog("error",
			"cannot fetch Vulnerabilities affecting device from DB: ", err.Error(),
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		dev := DeviceVADB{}

		err = rows.Scan(
			&dev.DeviceID,
			&dev.MgmtIPAddress,
			&dev.LastScan,
			&dev.EnterpriseID,
			&dev.ScanMeanTime,
			&dev.OSType,
			&dev.OSVersion,
			&dev.DeviceModel,
			&dev.SerialNumber,
			&dev.TotalVulnScanned,
		)

		if err != nil {
			logging.VulscanoLog("error",
				"error while scanning device_va_results table rows: ", err.Error())
			return nil, err
		}
		devSlice = append(devSlice, dev)
	}
	err = rows.Err()
	if err != nil {
		logging.VulscanoLog("error",
			"error returned while fetching vulnerabilities affecting device: ", err.Error())
		return nil, err
	}

	return devSlice, nil
}
func (p *vulscanoDB) AdminGetDevVAResultsByCVE(cve string, ent string) ([]DeviceVADB, error) {

	devSlice := make([]DeviceVADB, 0)

	// Normalize ent to Postgres NULL type if empty
	pEnt := normalizeString(ent)

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT device_id, mgmt_ip_address, last_successful_scan, enterprise_id,
					  scan_mean_time, os_type, os_version, device_model, 
 				      serial_number, total_vulnerabilities_scanned 
					  FROM device_va_results 
					  WHERE (
							SELECT advisory_id FROM cisco_advisories WHERE $1 = ANY(cve_id)
						    ) = ANY(vulnerabilities_found)
				      AND (enterprise_id = $2 OR $2 IS NULL)
				     `

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, cve, pEnt)

	if err != nil {
		logging.VulscanoLog("error",
			"cannot fetch Vulnerabilities affecting device from DB: ", err.Error(),
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		dev := DeviceVADB{}

		err = rows.Scan(
			&dev.DeviceID,
			&dev.MgmtIPAddress,
			&dev.LastScan,
			&dev.EnterpriseID,
			&dev.ScanMeanTime,
			&dev.OSType,
			&dev.OSVersion,
			&dev.DeviceModel,
			&dev.SerialNumber,
			&dev.TotalVulnScanned,
		)

		if err != nil {
			logging.VulscanoLog("error",
				"error while scanning device_va_results table rows: ", err.Error())
			return nil, err
		}
		devSlice = append(devSlice, dev)
	}
	err = rows.Err()
	if err != nil {
		logging.VulscanoLog("error",
			"error returned while fetching vulnerabilities affecting device: ", err.Error())
		return nil, err
	}

	return devSlice, nil
}

func (p *vulscanoDB) UserGetDevVAResultsByCVE(cve string, ent string) ([]DeviceVADB, error) {

	devSlice := make([]DeviceVADB, 0)

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT device_id, mgmt_ip_address, last_successful_scan, enterprise_id,
					  scan_mean_time, os_type, os_version, device_model, 
					  serial_number, total_vulnerabilities_scanned
					  FROM device_va_results 
					  WHERE (
							SELECT advisory_id FROM cisco_advisories WHERE $1 = ANY(cve_id)
						    ) = ANY(vulnerabilities_found)
				      AND enterprise_id = $2
				     `

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, cve, ent)

	if err != nil {
		logging.VulscanoLog("error",
			"cannot fetch Vulnerabilities affecting device from DB: ", err.Error(),
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		dev := DeviceVADB{}

		err = rows.Scan(
			&dev.DeviceID,
			&dev.MgmtIPAddress,
			&dev.LastScan,
			&dev.EnterpriseID,
			&dev.ScanMeanTime,
			&dev.OSType,
			&dev.OSVersion,
			&dev.DeviceModel,
			&dev.SerialNumber,
			&dev.TotalVulnScanned,
		)

		if err != nil {
			logging.VulscanoLog("error",
				"error while scanning device_va_results table rows: ", err.Error())
			return nil, err
		}
		devSlice = append(devSlice, dev)
	}
	err = rows.Err()
	if err != nil {
		logging.VulscanoLog("error",
			"error returned while fetching vulnerabilities affecting device: ", err.Error())
		return nil, err
	}

	return devSlice, nil
}
