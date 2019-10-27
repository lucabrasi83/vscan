package postgresdb

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v4"
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

type VulnDeviceDB struct {
	AdvisoryID           string    `json:"advisoryID"`
	AdvisoryTitle        string    `json:"advisoryTitle"`
	BugID                []string  `json:"bugID"`
	CVE                  []string  `json:"cve"`
	SecurityImpactRating string    `json:"sir"`
	CVSS                 float64   `json:"cvss"`
	FirstPublished       time.Time `json:"publicationDate"`
	PublicationURL       string    `json:"publicationURL"`
}

type VulnHistoryDeviceDB struct {
	ScanDate             time.Time `json:"scanDate"`
	VulnerabilitiesFound []string  `json:"vulnFound"`
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

func (p *vulscanoDB) GetDevVAResultsBySA(vuln string, ent string) ([]DeviceVADB, error) {

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
			"cannot fetch Vulnerabilities affecting device from DB %v", err,
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
				"error while scanning device_va_results table rows %v", err)
			return nil, err
		}
		devSlice = append(devSlice, dev)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching vulnerabilities affecting device %v", err)
		return nil, err
	}

	return devSlice, nil
}
func (p *vulscanoDB) GetDevVAResultsByCVE(cve string, ent string) ([]DeviceVADB, error) {

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
			"cannot fetch Vulnerabilities affecting device from DB %v", err,
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
				"error while scanning device_va_results table rows %v", err)
			return nil, err
		}
		devSlice = append(devSlice, dev)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching vulnerabilities affecting device %v", err)
		return nil, err
	}

	return devSlice, nil
}

func (p *vulscanoDB) DeleteDevices(ent string, dev []string) error {

	pEnt := normalizeString(ent)

	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	const sqlQuery = `DELETE FROM device_va_results
					  WHERE device_id = $1 
					  AND (enterprise_id = $2 OR $2 IS NULL)`

	defer cancelQuery()

	b := &pgx.Batch{}

	for _, d := range dev {
		b.Queue(sqlQuery, d, pEnt)
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

func (p *vulscanoDB) DBVulnDeviceHistory(dev string, ent string, limit int) ([]VulnHistoryDeviceDB, error) {

	devSlice := make([]VulnHistoryDeviceDB, 0)

	pDev := normalizeString(dev)
	pEnt := normalizeString(ent)

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT timestamp, vuln_found
					  FROM device_va_history
					  INNER JOIN device_va_results
					  ON device_va_results.device_id = device_va_history.device_id
				      WHERE device_va_results.device_id = $1
					  AND device_va_results.enterprise_id = $2 OR $2 IS NULL
					  ORDER BY timestamp ASC
					  LIMIT $3;
				     `

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, pDev, pEnt, limit)

	if err != nil {
		logging.VSCANLog("error",
			"cannot fetch Vulnerabilities device history from DB %v", err,
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		vuln := VulnHistoryDeviceDB{}

		err = rows.Scan(
			&vuln.ScanDate,
			&vuln.VulnerabilitiesFound,
		)

		if err != nil {
			logging.VSCANLog("error",
				"error while scanning device_va_results table rows %v", err)
			return nil, err
		}
		devSlice = append(devSlice, vuln)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching device vulnerability history %v", err)
		return nil, err
	}

	return devSlice, nil
}

func (p *vulscanoDB) DBVulnAffectingDevice(dev string, ent string) ([]VulnDeviceDB, error) {

	devSlice := make([]VulnDeviceDB, 0)

	pDev := normalizeString(dev)
	pEnt := normalizeString(ent)

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT advisory_id, advisory_title, bug_id, cve_id, security_impact_rating, 
				      cvss_base_score, publication_url, first_published
					  FROM cisco_advisories
					  INNER JOIN device_va_results
					  CROSS JOIN unnest(device_va_results.vulnerabilities_found) as vuln
					  ON LOWER(cisco_advisories.advisory_id) = LOWER(vuln)
				      WHERE device_va_results.device_id = $1
                      AND (device_va_results.enterprise_id = $2 OR $2 IS NULL);
				     `

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, pDev, pEnt)

	if err != nil {
		logging.VSCANLog("error",
			"cannot fetch Vulnerabilities affecting device from DB %v", err,
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		vuln := VulnDeviceDB{}

		err = rows.Scan(
			&vuln.AdvisoryID,
			&vuln.AdvisoryTitle,
			&vuln.BugID,
			&vuln.CVE,
			&vuln.SecurityImpactRating,
			&vuln.CVSS,
			&vuln.PublicationURL,
			&vuln.FirstPublished,
		)

		if err != nil {
			logging.VSCANLog("error",
				"error while scanning device_va_results table rows %v", err)
			return nil, err
		}
		devSlice = append(devSlice, vuln)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching vulnerabilities affecting device %v", err)
		return nil, err
	}

	return devSlice, nil
}
