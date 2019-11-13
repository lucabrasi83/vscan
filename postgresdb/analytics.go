package postgresdb

import (
	"context"

	"github.com/lucabrasi83/vscan/logging"
)

type TopCiscoSADB struct {
	AdvisoryID         string  `json:"advisoryID"`
	CVSSScore          float64 `json:"cvssScore"`
	PublicationURL     string  `json:"publicationURL"`
	VulnerabilityCount int     `json:"vulnerabilityCount"`
}

type TopCVEDB struct {
	CVE                string  `json:"cveID"`
	CVSSScore          float64 `json:"cvssScore"`
	PublicationURL     string  `json:"publicationURL"`
	VulnerabilityCount int     `json:"vulnerabilityCount"`
}

type TopEnterprisesAffected struct {
	EnterpriseID       string  `json:"enterpriseID"`
	EnterpriseName     string  `json:"enterpriseName"`
	CVSSScore          float64 `json:"cvssScore"`
	AdvisoryID         string  `json:"advisoryID"`
	VulnerabilityCount int     `json:"vulnerabilityCount"`
}

type TopOSAffected struct {
	OSType             string `json:"osType"`
	OSVersion          string `json:"osVersion"`
	CVSSScore          string `json:"cvssScore"`
	VulnerabilityCount int    `json:"vulnerabilityCount"`
}

func (p *vulscanoDB) TopCiscoSA(ent string) ([]TopCiscoSADB, error) {

	saSlice := make([]TopCiscoSADB, 0)

	pEnt := normalizeString(ent)

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT advisory_id, cvss_base_score, publication_url, COUNT(advisory_id) as count_vuln
				      FROM cisco_advisories
                      INNER JOIN device_va_results
                      CROSS JOIN unnest(device_va_results.vulnerabilities_found) as vuln
                      ON LOWER(cisco_advisories.advisory_id) = LOWER(vuln)
                      WHERE (device_va_results.enterprise_id = $1 OR $1 IS NULL)
                      GROUP BY advisory_id
                      ORDER BY count_vuln DESC;
				     `

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, pEnt)

	if err != nil {
		logging.VSCANLog("error",
			"cannot fetch Top Cisco SA Vulnerabilities affecting devices from DB %v", err,
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		vuln := TopCiscoSADB{}

		err = rows.Scan(
			&vuln.AdvisoryID,
			&vuln.CVSSScore,
			&vuln.PublicationURL,
			&vuln.VulnerabilityCount,
		)

		if err != nil {
			logging.VSCANLog("error",
				"error while scanning device_va_results table rows %v", err)
			return nil, err
		}
		saSlice = append(saSlice, vuln)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching Top Cisco SA vulnerabilities affecting devices %v", err)
		return nil, err
	}

	return saSlice, nil
}

func (p *vulscanoDB) TopCVE(ent string) ([]TopCVEDB, error) {

	cveSlice := make([]TopCVEDB, 0)

	pEnt := normalizeString(ent)

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT unnest(cve_id) AS CVE, cvss_base_score, publication_url, COUNT(advisory_id) as count_vuln
                      FROM cisco_advisories
                      INNER JOIN device_va_results
                      CROSS JOIN unnest(device_va_results.vulnerabilities_found) as vuln
                      ON LOWER(cisco_advisories.advisory_id) = LOWER(vuln)
                      WHERE (device_va_results.enterprise_id = $1 OR $1 IS NULL)
                      GROUP BY advisory_id
                      ORDER BY count_vuln DESC;
				     `

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, pEnt)

	if err != nil {
		logging.VSCANLog("error",
			"cannot fetch Top CVE Vulnerabilities affecting devices from DB %v", err,
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		vuln := TopCVEDB{}

		err = rows.Scan(
			&vuln.CVE,
			&vuln.CVSSScore,
			&vuln.PublicationURL,
			&vuln.VulnerabilityCount,
		)

		if err != nil {
			logging.VSCANLog("error",
				"error while scanning device_va_results table rows %v", err)
			return nil, err
		}
		cveSlice = append(cveSlice, vuln)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching Top Cisco SA vulnerabilities affecting device %v", err)
		return nil, err
	}

	return cveSlice, nil
}

func (p *vulscanoDB) TopEnterprisesAffected(ent string) ([]TopEnterprisesAffected, error) {

	enterpriseSlice := make([]TopEnterprisesAffected, 0)

	pEnt := normalizeString(ent)

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT  device_va_results.enterprise_id,enterprise.enterprise_name, 
                              cvss_base_score, publication_url, advisory_id, COUNT(advisory_id) as count_vuln
					  FROM cisco_advisories
				      INNER JOIN device_va_results
				      CROSS JOIN unnest(device_va_results.vulnerabilities_found) as vuln
					  ON LOWER(cisco_advisories.advisory_id) = LOWER(vuln)
					  INNER JOIN enterprise ON device_va_results.enterprise_id = enterprise.enterprise_id
					  WHERE (device_va_results.enterprise_id = $1 OR $1 IS NULL)
                      GROUP BY device_va_results.enterprise_id,enterprise.enterprise_name, 
                               cvss_base_score, publication_url, advisory_id
				      ORDER BY count_vuln DESC;
				     `

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, pEnt)

	if err != nil {
		logging.VSCANLog("error",
			"cannot fetch Top Enterprises affected from DB %v", err,
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		vuln := TopEnterprisesAffected{}

		err = rows.Scan(
			&vuln.EnterpriseID,
			&vuln.EnterpriseName,
			&vuln.CVSSScore,
			&vuln.AdvisoryID,
			&vuln.VulnerabilityCount,
		)

		if err != nil {
			logging.VSCANLog("error",
				"error while scanning device_va_results table rows %v", err)
			return nil, err
		}
		enterpriseSlice = append(enterpriseSlice, vuln)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching Top Enterprises affected %v", err)
		return nil, err
	}

	return enterpriseSlice, nil
}

func (p *vulscanoDB) TopOSAffected(ent string) ([]TopOSAffected, error) {

	osSlice := make([]TopOSAffected, 0)

	pEnt := normalizeString(ent)

	// Set Query timeout
	ctxTimeout, cancelQuery := context.WithTimeout(context.Background(), mediumQueryTimeout)

	const sqlQuery = `SELECT  os_version, os_type, cvss_base_score, COUNT(vuln) AS count_vuln
                      FROM cisco_advisories
                      INNER JOIN device_va_results
                      CROSS JOIN unnest(device_va_results.vulnerabilities_found) as vuln
                      ON LOWER(cisco_advisories.advisory_id) = LOWER(vuln)
                      WHERE (device_va_results.enterprise_id = $1 OR $1 IS NULL)
                      GROUP BY os_version, cvss_base_score, os_type
                      ORDER BY count_vuln DESC;
				     `

	defer cancelQuery()

	rows, err := p.db.Query(ctxTimeout, sqlQuery, pEnt)

	if err != nil {
		logging.VSCANLog("error",
			"cannot fetch Top OS affected from DB %v", err,
		)
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		vuln := TopOSAffected{}

		err = rows.Scan(
			&vuln.OSType,
			&vuln.OSVersion,
			&vuln.CVSSScore,
			&vuln.VulnerabilityCount,
		)

		if err != nil {
			logging.VSCANLog("error",
				"error while scanning device_va_results table rows %v", err)
			return nil, err
		}
		osSlice = append(osSlice, vuln)
	}
	err = rows.Err()
	if err != nil {
		logging.VSCANLog("error",
			"error returned while fetching Top OS affected %v", err)
		return nil, err
	}

	return osSlice, nil
}
