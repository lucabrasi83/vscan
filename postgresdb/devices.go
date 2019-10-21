package postgresdb

import (
	"context"
	"net"
	"time"

	"github.com/lucabrasi83/vscan/logging"
)

type DeviceVADB struct {
	DeviceID                   string    `json:"deviceID"`
	MgmtIPAddress              net.IP    `json:"mgmtIP"`
	LastScan                   time.Time `json:"lastScan"`
	EnterpriseID               string    `json:"enterpriseID"`
	EnterpriseName             string    `json:"enterpriseName"`
	ScanMeanTime               int       `json:"scanMeanTimeMilliseconds"`
	OSType                     string    `json:"osType"`
	OSVersion                  string    `json:"osVersion"`
	DeviceModel                string    `json:"deviceModel"`
	SerialNumber               string    `json:"serialNumber"`
	SuggestedSW                string    `json:"suggestedSW"`
	ProductID                  string    `json:"productID"`
	VulnerabilitiesFound       []string  `json:"vulnerabilitiesFound"`
	DeviceHostname             string    `json:"deviceHostname"`
	TotalVulnScanned           int       `json:"totalVulnScanned"`
	ServiceContractNumber      string    `json:"serviceContractNumber"`
	ServiceContractDescription string    `json:"serviceContractDescription"`
	ServiceContractEndDate     time.Time `json:"serviceContractEndDate"`
	ServiceContractSiteCountry string    `json:"serviceContractSiteCountry"`
	ServiceContractAssociated  bool      `json:"serviceContractAssociated"`
}

func (p *vulscanoDB) GetAllDevicesDB(ent string) ([]DeviceVADB, error) {

	pEnt := normalizeString(ent)

	vulscanoDevices := make([]DeviceVADB, 0)

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT t1.device_id, t1.serial_number, t1.mgmt_ip_address,
		              t1.last_successful_scan, t1.vulnerabilities_found, t1.enterprise_id,
                      t1.scan_mean_time, t1.os_type, t1.os_version, 
					  t1.device_model, t1.total_vulnerabilities_scanned,
                      t1.suggested_sw, t1.device_hostname, t1.product_id, t1.service_contract_number, 
                      t1.service_contract_description, t1.service_contract_end_date,
				      t1.service_contract_site_country, t1.service_contract_associated,
					  t2.enterprise_name 
					  FROM device_va_results t1, enterprise t2
				      WHERE t1.enterprise_id = $1 or $1 IS NULL
					  AND t1.enterprise_id = t2.enterprise_id
`

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, pEnt)

	if err != nil {
		logging.VSCANLog("error",
			"cannot fetch Devices from DB %v", err.Error(),
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		dev := DeviceVADB{}
		err = rows.Scan(
			&dev.DeviceID,
			&dev.SerialNumber,
			&dev.MgmtIPAddress,
			&dev.LastScan,
			&dev.VulnerabilitiesFound,
			&dev.EnterpriseID,
			&dev.ScanMeanTime,
			&dev.OSType,
			&dev.OSVersion,
			&dev.DeviceModel,
			&dev.TotalVulnScanned,
			&dev.SuggestedSW,
			&dev.DeviceHostname,
			&dev.ProductID,
			&dev.ServiceContractNumber,
			&dev.ServiceContractDescription,
			&dev.ServiceContractEndDate,
			&dev.ServiceContractSiteCountry,
			&dev.ServiceContractAssociated,
			&dev.EnterpriseName,
		)

		if err != nil {
			logging.VSCANLog("error",
				"error while scanning device_va_results table rows %v", err.Error())
			return nil, err
		}
		vulscanoDevices = append(vulscanoDevices, dev)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while iterating through device_va_results table %v", err.Error())
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
		logging.VSCANLog("error",
			"cannot fetch Vulnerabilities affecting device from DB %v", err.Error(),
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
			logging.VSCANLog("error",
				"error while scanning device_va_results table rows %v", err.Error())
			return nil, err
		}
		devSlice = append(devSlice, dev)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching vulnerabilities affecting device %v", err.Error())
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
		logging.VSCANLog("error",
			"cannot fetch Vulnerabilities affecting device from DB %v", err.Error(),
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
			logging.VSCANLog("error",
				"error while scanning device_va_results table rows %v", err.Error())
			return nil, err
		}
		devSlice = append(devSlice, dev)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching vulnerabilities affecting device %v", err.Error())
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
		logging.VSCANLog("error",
			"cannot fetch Vulnerabilities affecting device from DB %v", err.Error(),
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
			logging.VSCANLog("error",
				"error while scanning device_va_results table rows %v", err.Error())
			return nil, err
		}
		devSlice = append(devSlice, dev)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching vulnerabilities affecting device %v", err.Error())
		return nil, err
	}

	return devSlice, nil
}
