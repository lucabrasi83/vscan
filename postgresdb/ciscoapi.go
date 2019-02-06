package postgresdb

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/openvulnapi"
)

// insertAllCiscoAdvisories will fetch all Cisco published security advisories and store them in the DB
func (p *vulscanoDB) InsertAllCiscoAdvisories() error {

	logging.VulscanoLog(
		"info",
		"Fetching all published Cisco Security Advisories...")

	//var allSA *[]openvulnapi.VulnMetadata

	allSA, err := openvulnapi.GetAllVulnMetaData()

	if err != nil {
		logging.VulscanoLog(
			"error",
			"Failed to retrieve all Cisco Advisories from openVuln API: ",
			err.Error())

		return err
	}

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), longQueryTimeout)

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

	for _, adv := range allSA {

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
				strings.TrimSpace(adv.AdvisoryID),
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

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), shortQueryTimeout)

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

// UpdateDeviceSuggestedSW will update all Devices Suggested Software Version from Cisco API
func (p *vulscanoDB) UpdateDeviceSuggestedSW(devSW []map[string]string) error {

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), longQueryTimeout)

	// SQL Statement to insert all Cisco advisories Metadata from openVuln API
	// If Cisco Advisory ID already exists, we just update it with fields returned by Cisco openVuln API
	const sqlQuery = `UPDATE device_va_results SET suggested_sw = COALESCE($1, 'NA') WHERE device_id = $2`

	defer cancelQuery()

	// Prepare SQL Statement in DB for Batch
	_, err := p.db.Prepare("update_device_suggested_sw", sqlQuery)

	if err != nil {
		logging.VulscanoLog(
			"error",
			"Failed to prepare Batch statement: ",
			err.Error())
		return err
	}

	b := p.db.BeginBatch()

	for _, d := range devSW {

		b.Queue("update_device_suggested_sw",
			[]interface{}{
				d["suggestedVersion"],
				d["deviceID"],
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
