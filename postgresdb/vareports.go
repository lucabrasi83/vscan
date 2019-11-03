package postgresdb

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/lucabrasi83/vscan/logging"
)

type ScanJobsHistory struct {
	JobID              string    `json:"jobID"`
	StartDate          time.Time `json:"startTime"`
	EndDate            time.Time `json:"endTime"`
	DevicesScannedName []string  `json:"devicesScannedName"`
	DevicesScannedIP   []net.IP  `json:"devicesScannedIP"`
	JobStatus          string    `json:"jobStatus"`
	User               string    `json:"user"`
	Agent              string    `json:"agent"`
	JobLogs            string    `json:"jobLogs"`
}

func (p *vulscanoDB) GetScanJobsHistoryCounts(filters map[string]string, uid string) (int, error) {

	// Normalize filter strings to Postgres NULL type if empty
	pDevName := normalizeString(filters["deviceName"])
	pDevIP := normalizeString(filters["deviceIP"])
	pStartTime := normalizeString(filters["startTime"])
	pEndTime := normalizeString(filters["endTime"])
	pJobResult := normalizeString(filters["jobResult"])
	pUserID := normalizeString(uid)
	pLogPattern := normalizeString(filters["logPattern"])

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	sqlQuery := `
        SELECT COUNT(job_id)
        FROM   scan_jobs_history AS jobs
        WHERE (jobs.devices_scanned_name && 
              (ARRAY(SELECT device_id::text FROM device_va_results WHERE device_id::text ILIKE '%' || $1 || '%')) 
              OR $1 IS NULL)
        AND (ARRAY[$2]::inet[] && devices_scanned_ip OR $2 IS NULL)
        AND (jobs.start_time >= $3 OR $3 IS NULL)
        AND (jobs.end_time <= $4 OR $4 IS NULL )
        AND (jobs.job_result = $5 OR $5 IS NULL )
        AND (jobs.user_id_scan_request = $6 OR $6 IS NULL)
        AND (jobs.scan_logs::text ILIKE '%' || $7 || '%' OR $7 IS NULL)
        `

	defer cancelQuery()

	var countRec int

	countRow := p.db.QueryRow(
		ctxTimeout,
		sqlQuery,
		pDevName,
		pDevIP,
		pStartTime,
		pEndTime,
		pJobResult,
		pUserID,
		pLogPattern)

	err := countRow.Scan(&countRec)

	if err != nil {
		logging.VSCANLog("error",
			"cannot fetch Scan Jobs History Count from DB %v", err,
		)
		return 0, err
	}

	return countRec, nil

}

func (p *vulscanoDB) GetScanJobsHistoryResults(filters, order map[string]string, limit string,
	offset string, uid string) ([]ScanJobsHistory,
	error) {

	jobSlice := make([]ScanJobsHistory, 0)

	// Normalize filter strings to Postgres NULL type if empty
	pDevName := normalizeString(filters["deviceName"])
	pDevIP := normalizeString(filters["deviceIP"])
	pStartTime := normalizeString(filters["startTime"])
	pEndTime := normalizeString(filters["endTime"])
	pJobResult := normalizeString(filters["jobResult"])
	pUserID := normalizeString(uid)
	pLogPattern := normalizeString(filters["logPattern"])

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	sqlQuery := `
        SELECT jobs.job_id, jobs.start_time, jobs.end_time, jobs.job_result, users.email,
               jobs.devices_scanned_name, jobs.devices_scanned_ip, jobs.scan_exec_agent, jobs.scan_logs
        FROM   scan_jobs_history AS jobs
        INNER JOIN vulscano_users AS users
		ON jobs.user_id_scan_request = users.user_id
        WHERE (jobs.devices_scanned_name && 
              (ARRAY(SELECT device_id::text FROM device_va_results WHERE device_id::text ILIKE '%' || $1 || '%')) 
              OR $1 IS NULL)
        AND (ARRAY[$2]::inet[] && devices_scanned_ip OR $2 IS NULL)
        AND (jobs.start_time >= $3 OR $3 IS NULL)
        AND (jobs.end_time <= $4 OR $4 IS NULL )
        AND (jobs.job_result = $5 OR $5 IS NULL )
        AND (jobs.user_id_scan_request = $6 OR $6 IS NULL)
        AND (jobs.scan_logs::text ILIKE '%' || $7 || '%' OR $7 IS NULL)
        ORDER BY jobs.` + order["column"] + " " + order["direction"] + `
		LIMIT $8
		OFFSET $9
        `

	defer cancelQuery()

	rows, err := p.db.Query(
		ctxTimeout,
		sqlQuery,
		pDevName,
		pDevIP,
		pStartTime,
		pEndTime,
		pJobResult,
		pUserID,
		pLogPattern,
		limit,
		offset,
	)

	if err != nil {
		logging.VSCANLog("error",
			"cannot fetch Scan Jobs History from DB %v", err,
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		job := ScanJobsHistory{}

		err = rows.Scan(
			&job.JobID,
			&job.StartDate,
			&job.EndDate,
			&job.JobStatus,
			&job.User,
			&job.DevicesScannedName,
			&job.DevicesScannedIP,
			&job.Agent,
			&job.JobLogs,
		)

		if err != nil {
			logging.VSCANLog("error",
				"error while scanning scan_jobs_history table rows %v", err)
			return nil, err
		}
		jobSlice = append(jobSlice, job)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching scan jobs %v", err)
		return nil, err
	}

	return jobSlice, nil
}

func (p *vulscanoDB) PersistScanJobReport(args ...interface{}) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	// SQL Query to insert VA Job stats
	const sqlQueryJobReport = `INSERT INTO scan_jobs_history
							   (job_id, start_time, end_time, 
							    devices_scanned_name, devices_scanned_ip, 
								job_result, user_id_scan_request, scan_exec_agent, scan_logs)
						        VALUES ($1, $2, $3, COALESCE($4, '{}'::text[]), 
			 			        COALESCE($5, '{}'::inet[]), $6, $7, $8, $9)
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
			logging.VSCANLog("error", "Failed to close SQL Batch Job for query %v with error %v", sqlQueryDeviceReport, errCloseBatch)
		}
	}()

	c, errSendBatch := r.Exec()

	if errSendBatch != nil {
		logging.VSCANLog(
			"error",
			"Failed to send Batch query %v with error: %v", sqlQueryDeviceReport, errSendBatch.Error())

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
				"Failed to close SQL Batch Job query %v with error %v", sqlQueryDeviceHistory, errCloseBatch)
		}
	}()

	c, errSendBatch := r.Exec()

	if errSendBatch != nil {
		logging.VSCANLog(
			"error",
			"Failed to send Batch query %v with error %v", sqlQueryDeviceHistory, errSendBatch.Error())

		return errSendBatch

	}

	if c.RowsAffected() < 1 {
		return fmt.Errorf("no insertion of row while executing query %v", sqlQueryDeviceHistory)
	}

	return nil
}
