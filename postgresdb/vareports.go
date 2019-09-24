package postgresdb

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4"
	"github.com/lucabrasi83/vscan/logging"
)

func (p *vulscanoDB) PersistScanJobReport(args ...interface{}) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	// SQL Query to insert VA Job stats
	const sqlQueryJobReport = `INSERT INTO scan_jobs_history
							   (job_id, start_time, end_time, 
							    devices_scanned_name, devices_scanned_ip, 
								job_result, user_id_scan_request, scan_exec_agent)
						       VALUES ($1, $2, $3, COALESCE($4, '{}'::text[]), COALESCE($5, '{}'::inet[]), $6, $7, $8)
							  `

	defer cancelQuery()

	cTag, err := p.db.Exec(ctxTimeout, sqlQueryJobReport, args...)

	if err != nil {
		return err
	}

	if cTag.RowsAffected() == 0 {
		return fmt.Errorf("failed to insert Scan Job Reports in DB for job %v", args[0])
	}

	return nil
}

func (p *vulscanoDB) PersistDeviceVAJobReport(args ...interface{}) error {

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	// SQL Query to insert VA Scan Result per device
	const sqlQueryDeviceReport = `INSERT INTO device_va_results
  								  (device_id, mgmt_ip_address, last_successful_scan, 
                                  vulnerabilities_found, total_vulnerabilities_scanned,
							      enterprise_id, scan_mean_time, os_type, os_version, 
								  device_model, serial_number, device_hostname)
								  VALUES ($1, $2, $3, COALESCE($4, '{}'::text[]), $5, $6, $7, 
							      COALESCE($8, 'NA'), COALESCE($9, 'NA'), COALESCE($10, 'NA'), 
							      COALESCE($11, 'NA'), COALESCE($12, 'NA'))
								  ON CONFLICT (device_id)
								  DO UPDATE SET
								  mgmt_ip_address = EXCLUDED.mgmt_ip_address,
								  last_successful_scan = EXCLUDED.last_successful_scan,
								  vulnerabilities_found = COALESCE(EXCLUDED.vulnerabilities_found, '{}'::text[]),
							      total_vulnerabilities_scanned = EXCLUDED.total_vulnerabilities_scanned,
								  enterprise_id = EXCLUDED.enterprise_id,
								  scan_mean_time = EXCLUDED.scan_mean_time,
							      os_type = COALESCE(EXCLUDED.os_type, 'NA'),
								  os_version = COALESCE(EXCLUDED.os_version, 'NA'),
								  device_model = COALESCE(EXCLUDED.device_model, 'NA'),
								  serial_number = COALESCE(EXCLUDED.serial_number, 'NA'),
						          device_hostname = COALESCE(EXCLUDED.device_hostname, 'NA')
								 `

	defer cancelQuery()

	cTag, err := p.db.Exec(ctxTimeout, sqlQueryDeviceReport, args...)

	if err != nil {
		return err
	}

	if cTag.RowsAffected() == 0 {
		return fmt.Errorf("failed to insert Device VA results in DB")
	}

	return nil
}
func (p *vulscanoDB) PersistDeviceVAHistory(args ...interface{}) error {

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

	// SQL Query to insert VA Scan Result per device
	const sqlQueryDeviceHistory = `INSERT INTO device_va_history
  								  (device_id, vuln_found, timestamp)
								  VALUES ($1, $2, $3)
								 `

	defer cancelQuery()

	cTag, err := p.db.Exec(ctxTimeout, sqlQueryDeviceHistory, args...)

	if err != nil {
		return err
	}

	if cTag.RowsAffected() == 0 {
		return fmt.Errorf("failed to insert Device VA results in DB")
	}

	return nil
}

func (p *vulscanoDB) PersistBulkDeviceVAReport(args []map[string]interface{}) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), longQueryTimeout)

	const sqlQueryDeviceReport = `INSERT INTO device_va_results
  								  (device_id, mgmt_ip_address, last_successful_scan, 
                                  vulnerabilities_found, total_vulnerabilities_scanned,
							      enterprise_id, scan_mean_time, os_type, os_version, 
								  device_model, serial_number, device_hostname)
								  VALUES ($1, $2, $3, COALESCE($4, '{}'::text[]), $5, $6, $7, 
							      COALESCE($8, 'NA'), COALESCE($9, 'NA'), COALESCE($10, 'NA'), 
							      COALESCE($11, 'NA'), COALESCE($12, 'NA'))
								  ON CONFLICT (device_id)
								  DO UPDATE SET
								  mgmt_ip_address = EXCLUDED.mgmt_ip_address,
								  last_successful_scan = EXCLUDED.last_successful_scan,
								  vulnerabilities_found = COALESCE(EXCLUDED.vulnerabilities_found, '{}'::text[]),
							      total_vulnerabilities_scanned = EXCLUDED.total_vulnerabilities_scanned,
								  enterprise_id = EXCLUDED.enterprise_id,
								  scan_mean_time = EXCLUDED.scan_mean_time,
							      os_type = COALESCE(EXCLUDED.os_type, 'NA'),
								  os_version = COALESCE(EXCLUDED.os_version, 'NA'),
								  device_model = COALESCE(EXCLUDED.device_model, 'NA'),
								  serial_number = COALESCE(EXCLUDED.serial_number, 'NA'),
						          device_hostname = COALESCE(EXCLUDED.device_hostname, 'NA')
								 `

	defer cancelQuery()

	b := &pgx.Batch{}

	for _, d := range args {

		b.Queue(sqlQueryDeviceReport,
			d["deviceName"],
			d["deviceIP"],
			d["lastScan"],
			d["advisoryID"],
			d["totalVulnScanned"],
			d["enterpriseID"],
			d["scanMeantime"],
			d["osType"],
			d["osVersion"],
			d["deviceModel"],
			d["serialNumber"],
			d["deviceHostname"],
		)
	}

	// Send Batch SQL Query
	r := p.db.SendBatch(ctxTimeout, b)

	// Close Batch at the end of function
	defer func() {
		errCloseBatch := r.Close()
		if errCloseBatch != nil {
			logging.VSCANLog("error",
				fmt.Sprintf("Failed to close SQL Batch Job with error %v", errCloseBatch))
		}
	}()

	c, errSendBatch := r.Exec()

	if errSendBatch != nil {
		logging.VSCANLog(
			"error",
			"Failed to send Batch query: ",
			errSendBatch.Error())

		return errSendBatch

	}

	if c.RowsAffected() < 1 {
		return fmt.Errorf("no insertion of row while executing query %v", sqlQueryDeviceReport)
	}

	return nil
}

func (p *vulscanoDB) PersistBulkDeviceVAHistory(args []map[string]interface{}) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), longQueryTimeout)

	const sqlQueryDeviceHistory = `INSERT INTO device_va_history
  								  (device_id, vuln_found, timestamp)
								  VALUES ($1, $2, $3)
								 `

	defer cancelQuery()

	b := &pgx.Batch{}

	for _, d := range args {

		b.Queue(sqlQueryDeviceHistory,
			d["deviceName"],
			d["advisoryID"],
			d["lastScan"],
		)
	}

	// Send Batch SQL Query
	r := p.db.SendBatch(ctxTimeout, b)

	// Close Batch at the end of function
	defer func() {
		errCloseBatch := r.Close()
		if errCloseBatch != nil {
			logging.VSCANLog("error",
				fmt.Sprintf("Failed to close SQL Batch Job with error %v", errCloseBatch))
		}
	}()

	c, errSendBatch := r.Exec()

	if errSendBatch != nil {
		logging.VSCANLog(
			"error",
			"Failed to send Batch query: ",
			errSendBatch.Error())

		return errSendBatch

	}

	if c.RowsAffected() < 1 {
		return fmt.Errorf("no insertion of row while executing query %v", sqlQueryDeviceHistory)
	}

	return nil
}
