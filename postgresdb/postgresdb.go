// Package postgresdb handles connection and SQL queries to Vulscano Postgres DB
package postgresdb

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/jackc/pgx/pgtype"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx"
	_ "github.com/lucabrasi83/vulscano/initializer" // Import for correct init functions order
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/openvulnapi"
)

// ConnPool represents the Connection Pool instance
// db represents an instance of Postgres connection pool
var ConnPool *pgx.ConnPool
var DBInstance *vulscanoDB

type vulscanoDB struct {
	db *pgx.ConnPool
}

type VulscanoDBUser struct {
	UserID       string
	Email        string
	Role         string
	EnterpriseID string
}

type DeviceVADB struct {
	DeviceID         string
	MgmtIPAddress    net.IP
	LastScan         time.Time
	EnterpriseID     string
	ScanMeanTime     int
	OSType           string
	OSVersion        string
	DeviceModel      string
	TotalVulnScanned int
}

// init() function will establish DB connection pool while package is being loaded.
func init() {

	// Check Environment Variables for Postgres DB Credentials
	if os.Getenv("VULSCANO_DB_USERNAME") == "" || os.Getenv("VULSCANO_DB_PASSWORD") == "" {
		logging.VulscanoLog("fatal",
			"Missing Environment Variable(s) for PostgresDB Connection not set ",
			"(VULSCANO_DB_USERNAME / VULSCANO_DB_PASSWORD)")
	}

	var err error

	connPoolConfig := pgx.ConnPoolConfig{
		ConnConfig: pgx.ConnConfig{
			Host: "vulscano-db", // To be moved to Environment Variable
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			User:     os.Getenv("VULSCANO_DB_USERNAME"), // To be moved to Environment Variable
			Password: os.Getenv("VULSCANO_DB_PASSWORD"), // To be moved to Environment Variable
			Database: "vulscanodb",
		},
		MaxConnections: 20,
	}

	ConnPool, err = pgx.NewConnPool(connPoolConfig)

	if err != nil {
		logging.VulscanoLog(
			"fatal",
			"Unable to Create Postgres Connection Pool: ",
			err.Error())
	} else {
		logging.VulscanoLog("info", "Database Connection Pool successfully created")
	}

	// Instantiate DB object after successful connection
	DBInstance = newDBPool(ConnPool)

	postgresVersion := DBInstance.displayPostgresVersion()

	logging.VulscanoLog("info", "Postgres SQL Version: ", postgresVersion)

	//rows, err := b.QueryResults()
	//
	//if err != nil {
	//	logging.VulscanoLog(
	//		"error",
	//		"Failed to execute SQL query: ",
	//		err.Error())
	//}
	//defer rows.Close()
	//
	//for rows.Next() {
	//	var user string
	//	err = rows.Scan(&user)
	//	if err != nil {
	//		logging.VulscanoLog(
	//			"error",
	//			"Failed to parse SQL query: ",
	//			err.Error())
	//	}
	//	fmt.Println(user)
	//}
	//
	//err = rows.Err()
	//
	//if err != nil {
	//	logging.VulscanoLog(
	//		"error",
	//		"Iterating through SQL query returned error: ",
	//		err.Error())
	//}
}

func newDBPool(pool *pgx.ConnPool) *vulscanoDB {

	return &vulscanoDB{
		db: pool,
	}
}

func (p *vulscanoDB) displayPostgresVersion() string {
	var version string

	// Set Query timeout to 1 sec
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1000*time.Millisecond)

	defer cancelQuery()

	err := p.db.QueryRowEx(ctxTimeout, "SELECT version()", nil).Scan(&version)

	if err != nil {
		logging.VulscanoLog(
			"error",
			"Failed to retrieve Postgres Version: ",
			err.Error())
	}

	return version

}

// insertAllCiscoAdvisories will fetch all Cisco published security advisories and store them in the DB
func (p *vulscanoDB) InsertAllCiscoAdvisories() error {

	logging.VulscanoLog(
		"info",
		"Fetching all published Cisco Security Advisories...")

	var allSA *[]openvulnapi.VulnMetadata

	allSA, err := openvulnapi.GetAllVulnMetaData()

	if err != nil {
		logging.VulscanoLog(
			"error",
			"Failed to retrieve all Cisco Advisories from openVuln API: ",
			err.Error())

		return err
	}

	// Set Query timeout to 10 minutes
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 10*time.Minute)

	// SQL Statement to insert all Cisco advisories Metadata from openVuln API
	// If Cisco Advisory ID already exists, we just update it with fields returned by Cisco openVuln API
	const sqlQuery = `INSERT INTO cisco_advisories (advisory_id, advisory_title, first_published, bug_id, cve_id,
					  security_impact_rating, cvss_base_score, publication_url)
					  VALUES
					  ($1, $2, $3, $4, $5, $6, $7, $8)
					  ON CONFLICT (advisory_id)
				      DO UPDATE SET
					  advisory_title = EXCLUDED.advisory_title,
                      first_published = EXCLUDED.first_published,
                      bug_id = EXCLUDED.bug_id,
                      cve_id = EXCLUDED.cve_id,
                      security_impact_rating = EXCLUDED.security_impact_rating,
                      cvss_base_score = EXCLUDED.cvss_base_score,
                      publication_url = EXCLUDED.publication_url
					`

	defer cancelQuery()

	// Prepare SQL Statement in DB for Batch
	_, err = p.db.Prepare("insert_all_cisco_advisories", sqlQuery)

	if err != nil {
		logging.VulscanoLog(
			"error",
			"Failed to prepare Batch statement: ",
			err.Error())
		return err
	}

	b := p.db.BeginBatch()

	for _, adv := range *allSA {

		// Convert openVuln API CVSS Score String to float
		var cvssScoreFloat float64
		var errFloatConver error

		if adv.CVSSBaseScore != "NA" {
			cvssScoreFloat, errFloatConver = strconv.ParseFloat(adv.CVSSBaseScore, 2)

			if errFloatConver != nil {
				logging.VulscanoLog(
					"error",
					"Failed to Convert CVSS Score String to Float for advisory: ",
					adv.AdvisoryID,
					errFloatConver.Error())

				return errFloatConver

			}
		}

		// Format openVuln API Timestamps string to comply with RFC3339 Time type
		formatTimeReplacer := strings.NewReplacer("0800", "08:00", "0700", "07:00", "0500", "05:00")
		formattedTime := formatTimeReplacer.Replace(adv.FirstPublished)

		// Convert openVuln API Time string to type Time
		timeStamps, _ := time.Parse(time.RFC3339, formattedTime)

		b.Queue("insert_all_cisco_advisories",
			[]interface{}{
				adv.AdvisoryID,
				adv.AdvisoryTitle,
				timeStamps,
				adv.BugID,
				adv.CVE,
				adv.SecurityImpactRating,
				cvssScoreFloat,
				adv.PublicationURL,
			},
			nil, nil)
	}

	// Send Batch SQL Query
	errSendBatch := b.Send(ctxTimeout, nil)
	if errSendBatch != nil {
		logging.VulscanoLog(
			"error",
			"Failed to send Batch query: ",
			errSendBatch.Error())

		return errSendBatch

	}

	// Execute Batch SQL Query
	errExecBatch := b.Close()
	if errExecBatch != nil {
		logging.VulscanoLog(
			"error",
			"Failed to execute Batch query: ",
			errExecBatch.Error())

		return errExecBatch
	}
	return nil
}

func (p *vulscanoDB) FetchCiscoSAMeta(sa string) *openvulnapi.VulnMetadata {

	var saMetaDB openvulnapi.VulnMetadata
	var timestamps time.Time
	var cvssScore float64

	// Set Query timeout to 1 sec
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 10*time.Second)

	const sqlQuery = `SELECT 
					  advisory_title, first_published, bug_id, cve_id, 
					  security_impact_rating, cvss_base_score, publication_url
					  FROM cisco_advisories
					  WHERE advisory_id = $1
					 `

	defer cancelQuery()

	row := p.db.QueryRowEx(ctxTimeout, sqlQuery, nil, sa)

	err := row.Scan(
		&saMetaDB.AdvisoryTitle,
		&timestamps,
		&saMetaDB.BugID,
		&saMetaDB.CVE,
		&saMetaDB.SecurityImpactRating,
		&cvssScore,
		&saMetaDB.PublicationURL)

	switch err {
	case pgx.ErrNoRows:
		logging.VulscanoLog(
			"error",
			"No entries found for Cisco Security Advisory ", sa)

	case nil:
		// Convert Vulnerability published date from Time type to string
		saMetaDB.FirstPublished = timestamps.In(time.UTC).Format(time.RFC3339)
		saMetaDB.AdvisoryID = sa

		// Convert Vulnerability CVSS Base Score from float64 type to string
		saMetaDB.CVSSBaseScore = strconv.FormatFloat(cvssScore, 'f', 1, 64)

		return &saMetaDB

	default:
		logging.VulscanoLog(
			"error", "Error while fetching Cisco SA metadata for ", sa, err.Error())
	}

	return &saMetaDB
}

func (p *vulscanoDB) PersistScanJobReport(args ...interface{}) error {

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	// SQL Query to insert VA Job stats
	const sqlQueryJobReport = `INSERT INTO scan_jobs_history
							   (job_id, start_time, end_time, devices_scanned_name, devices_scanned_ip, 
								job_result, user_id_scan_request)
						       VALUES ($1, $2, $3, $4, $5, $6, $7)
							  `

	defer cancelQuery()

	cTag, err := p.db.ExecEx(ctxTimeout, sqlQueryJobReport, nil, args...)

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
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	// SQL Query to insert VA Scan Result per device
	const sqlQueryDeviceReport = `INSERT INTO device_va_results
  								  (device_id, mgmt_ip_address, last_successful_scan, 
                                  vulnerabilities_found, total_vulnerabilities_scanned,
							      enterprise_id, scan_mean_time, os_type, os_version, device_model)
								  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
								  ON CONFLICT (device_id)
								  DO UPDATE SET
								  mgmt_ip_address = EXCLUDED.mgmt_ip_address,
								  last_successful_scan = EXCLUDED.last_successful_scan,
								  vulnerabilities_found = EXCLUDED.vulnerabilities_found,
							      total_vulnerabilities_scanned = EXCLUDED.total_vulnerabilities_scanned,
								  enterprise_id = EXCLUDED.enterprise_id,
								  scan_mean_time = EXCLUDED.scan_mean_time,
							      os_type = EXCLUDED.os_type,
								  os_version = EXCLUDED.os_version,
								  device_model = EXCLUDED.device_model
								 `

	defer cancelQuery()

	cTag, err := p.db.ExecEx(ctxTimeout, sqlQueryDeviceReport, nil, args...)

	if err != nil {
		return err
	}

	if cTag.RowsAffected() == 0 {
		return fmt.Errorf("failed to insert Device VA results in DB")
	}

	return nil
}

func (p *vulscanoDB) AuthenticateUser(user string, pass string) (*VulscanoDBUser, error) {

	var uDB VulscanoDBUser

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	const sqlQuery = `SELECT user_id, email, enterprise_id, role 
				      FROM vulscano_users WHERE 
                      email = $1 AND
                      password = crypt($2, password)
					 `

	defer cancelQuery()

	row := p.db.QueryRowEx(ctxTimeout, sqlQuery, nil, user, pass)

	err := row.Scan(
		&uDB.UserID,
		&uDB.Email,
		&uDB.EnterpriseID,
		&uDB.Role,
	)

	switch err {
	case pgx.ErrNoRows:
		logging.VulscanoLog(
			"error",
			"Authentication Failed for user: ", user)

		return nil, fmt.Errorf("authentication failed for user %v", user)

	case nil:

		return &uDB, nil

	default:
		logging.VulscanoLog(
			"error", "Error while authenticating user: ", user, err.Error())

		return nil, fmt.Errorf("authentication failed for user %v", user)
	}

}
func (p *vulscanoDB) FetchAllUsers() (*[]VulscanoDBUser, error) {

	var vulscanoUsers []VulscanoDBUser

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	const sqlQuery = `SELECT user_id, email, enterprise_id, role FROM vulscano_users`

	defer cancelQuery()

	rows, err := p.db.QueryEx(ctxTimeout, sqlQuery, nil)

	if err != nil {
		logging.VulscanoLog("error",
			"cannot fetch Users from DB: ", err.Error(),
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		user := VulscanoDBUser{}
		err = rows.Scan(&user.UserID, &user.Email, &user.EnterpriseID, &user.Role)

		if err != nil {
			logging.VulscanoLog("error",
				"error while scanning vulscano_users table rows: ", err.Error())
			return nil, err
		}
		vulscanoUsers = append(vulscanoUsers, user)
	}
	err = rows.Err()
	if err != nil {
		logging.VulscanoLog("error",
			"error returned while iterating through vulscano_users table: ", err.Error())
		return nil, err
	}

	return &vulscanoUsers, nil

}

func (p *vulscanoDB) FetchUser(u string) (*VulscanoDBUser, error) {

	var user VulscanoDBUser

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	const sqlQuery = `SELECT user_id, email, enterprise_id, role
				      FROM vulscano_users WHERE 
                      email = $1
					 `

	defer cancelQuery()

	row := p.db.QueryRowEx(ctxTimeout, sqlQuery, nil, u)

	err := row.Scan(&user.UserID, &user.Email, &user.EnterpriseID, &user.Role)

	switch err {
	case pgx.ErrNoRows:
		logging.VulscanoLog("error", "not able to find user requested in DB: ", u)
		return nil, fmt.Errorf("not able to find user %v requested in DB", u)

	case nil:
		return &user, nil

	default:
		logging.VulscanoLog("error", "error while trying to retrieve user from DB: ", err.Error())
		return nil, err
	}
}

func (p *vulscanoDB) InsertNewUser(email string, pass string, ent string, role string) error {

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	const sqlQuery = `INSERT INTO vulscano_users
					  (email, password, enterprise_id, role)
					  VALUES ($1, crypt($2, gen_salt('bf',8)), $3, $4)
					 `

	defer cancelQuery()

	cTag, err := p.db.ExecEx(ctxTimeout, sqlQuery, nil, email, pass, ent, role)

	if err != nil {
		logging.VulscanoLog("error",
			"failed to insert user: ", email, " ", err.Error())

		if strings.Contains(err.Error(), "23505") {
			return fmt.Errorf("user with email %v already exists", email)
		}
		if strings.Contains(err.Error(), "23503") {
			return fmt.Errorf("enterprise ID %v does not exist", ent)
		}
		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VulscanoLog("error",
			"failed to insert user: ", email)
		return fmt.Errorf("failed to insert user %v", email)
	}

	return nil
}
func (p *vulscanoDB) DeleteUser(email string) error {

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	const sqlQuery = `DELETE FROM vulscano_users
					  WHERE email = $1
					 `

	defer cancelQuery()

	cTag, err := p.db.ExecEx(ctxTimeout, sqlQuery, nil, email)

	if err != nil {
		logging.VulscanoLog("error",
			"failed to delete user: ", email, " ", err.Error())

		return err
	}

	if cTag.RowsAffected() == 0 {

		logging.VulscanoLog("error",
			"failed to delete user: ", email)
		return fmt.Errorf("failed to delete user %v", email)
	}

	return nil
}
func (p *vulscanoDB) PatchUser(email string, role string, pass string, ent string) error {

	pRole := &role
	pEnterprise := &ent
	pPassword := &pass

	// Set parameters values to NULL if empty
	if role == "" {
		errNullAssign := pgtype.NullAssignTo(&pRole)
		if errNullAssign != nil {
			logging.VulscanoLog("error",
				"failed to assigned NULL to role field ", errNullAssign.Error())
			return fmt.Errorf("error while processing role %v update", role)
		}
	}

	if ent == "" {
		errNullAssign := pgtype.NullAssignTo(&pEnterprise)
		if errNullAssign != nil {
			logging.VulscanoLog("error",
				"failed to assigned NULL to enterprise field ", errNullAssign.Error())
			return fmt.Errorf("error while processing enterprise %v update", ent)
		}
	}

	if pass == "" {
		errNullAssign := pgtype.NullAssignTo(&pPassword)
		if errNullAssign != nil {
			logging.VulscanoLog("error",
				"failed to assigned NULL to password field ", errNullAssign.Error())
			return fmt.Errorf("error while processing enterprise %v update", pass)
		}
	}

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	const sqlQuery = `UPDATE vulscano_users SET
			          password = COALESCE(crypt($1, gen_salt('bf', 8)), password),
				      enterprise_id = COALESCE($2, enterprise_id),
					  role = COALESCE($3, role)
					  WHERE email = $4
					 `

	defer cancelQuery()

	cTag, err := p.db.ExecEx(ctxTimeout, sqlQuery, nil,
		pPassword,
		pEnterprise,
		pRole,
		email)

	if err != nil {
		logging.VulscanoLog("error",
			"failed to update user: ", email, " ", err.Error())

		return err
	}

	if cTag.RowsAffected() == 0 {
		logging.VulscanoLog("error",
			"failed to update user: ", email)
		return fmt.Errorf("failed to update user %v", email)
	}

	return nil
}

func (p *vulscanoDB) AdminGetDevVAResultsBySA(vuln string, ent string) (*[]DeviceVADB, error) {

	var devSlice []DeviceVADB

	pEnt := &ent
	// Set parameters values to NULL if empty
	if ent == "" {
		errNullAssign := pgtype.NullAssignTo(&pEnt)
		if errNullAssign != nil {
			logging.VulscanoLog("error",
				"failed to assigned NULL to enterprise field ", errNullAssign.Error())
			return nil, fmt.Errorf("error while processing enterprise %v update", ent)
		}
	}

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	const sqlQuery = `SELECT device_id, mgmt_ip_address, last_successful_scan, enterprise_id,
					  scan_mean_time, os_type, os_version, device_model, total_vulnerabilities_scanned
					  FROM device_va_results 
					  WHERE $1 = ANY(vulnerabilities_found)
					  AND (enterprise_id = $2 OR $2 IS NULL)
				     `

	defer cancelQuery()

	rows, err := p.db.QueryEx(ctxTimeout, sqlQuery, nil, vuln, pEnt)

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

	return &devSlice, nil
}
func (p *vulscanoDB) AdminGetDevVAResultsByCVE(cve string, ent string) (*[]DeviceVADB, error) {

	var devSlice []DeviceVADB

	pEnt := &ent
	// Set parameters values to NULL if empty
	if ent == "" {
		errNullAssign := pgtype.NullAssignTo(&pEnt)
		if errNullAssign != nil {
			logging.VulscanoLog("error",
				"failed to assigned NULL to enterprise field ", errNullAssign.Error())
			return nil, fmt.Errorf("error while processing enterprise %v update", ent)
		}
	}

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	const sqlQuery = `SELECT device_id, mgmt_ip_address, last_successful_scan, enterprise_id,
					  scan_mean_time, os_type, os_version, device_model, total_vulnerabilities_scanned
					  FROM device_va_results 
					  WHERE (
							SELECT advisory_id FROM cisco_advisories WHERE $1 = ANY(cve_id)
						    ) = ANY(vulnerabilities_found)
				      AND (enterprise_id = $2 OR $2 IS NULL)
				     `

	defer cancelQuery()

	rows, err := p.db.QueryEx(ctxTimeout, sqlQuery, nil, cve, pEnt)

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

	return &devSlice, nil
}

func (p *vulscanoDB) AssertUserExists(id interface{}) bool {

	var u string

	// Set Query timeout to 1 minute
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), 1*time.Minute)

	const sqlQuery = `SELECT user_id
				      FROM vulscano_users WHERE 
                      email = $1
					 `

	defer cancelQuery()

	row := p.db.QueryRowEx(ctxTimeout, sqlQuery, nil, id)

	err := row.Scan(&u)

	switch err {
	case pgx.ErrNoRows:
		logging.VulscanoLog(
			"error", "User ", id, " tried to access but doesn't exist in database.")
		return false

	case nil:

		return true

	default:
		logging.VulscanoLog(
			"error", "Error while asserting user exists in Database: ", err.Error())

		return false
	}

}
