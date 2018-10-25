package handlers

import (
	"fmt"
	"github.com/gin-gonic/gin/json"
	"github.com/lucabrasi83/vulscano/datadiros"
	"github.com/lucabrasi83/vulscano/hashgen"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/openvulnapi"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CiscoIOSXEDevice struct {
	jovalURL string
}

type CiscoIOSDevice struct {
	jovalURL string
}

type ScanResults struct {
	ScanJobID                   string                      `json:"scan_job_id"`
	ScanJobStartTime            string                      `json:"scan_job_start_time"`
	ScanJobEndTime              string                      `json:"scan_job_end_time"`
	ScanDeviceMeanTime          string                      `json:"scan_job_device_mean_time"`
	TotalVulnerabilitiesFound   int                         `json:"total_vulnerabilities_found"`
	VulnerabilitiesFoundDetails *[]openvulnapi.VulnMetadata `json:"vulnerabilities_found_details"`
}

// Scan ReportFile represents the JSON report file created for each device by Joval scan
type ScanReportFile struct {
	DeviceName  string                  `json:"fact_friendlyname"`
	RuleResults []*ScanReportFileResult `json:"rule_results"`
}

// ScanReportFileResult represents the rule_result section of the JSON report file
type ScanReportFileResult struct {
	RuleResult     string                            `json:"rule_result"`
	RuleIdentifier []*ScanReportFileResultIdentifier `json:"rule_identifiers"`
}

// ScanReportFileResultIdentifier represents the rule_identifiers section of the JSON report file
type ScanReportFileResultIdentifier struct {
	ResultCiscoSA string `json:"identifier"`
}

// TODO: Create Scanner interface type to better handle multi-vendor VA Scans
type Scanner interface {
	Scan()
}

func newCiscoIOSXEDevice() *CiscoIOSXEDevice {
	d := CiscoIOSXEDevice{
		jovalURL: "http://download.jovalcm.com/content/cisco.iosxe.cve.oval.xml",
	}
	return &d
}
func newCiscoIOSDevice() *CiscoIOSXEDevice {
	d := CiscoIOSXEDevice{
		jovalURL: "http://download.jovalcm.com/content/cisco.ios.cve.oval.xml",
	}
	return &d
}

// Scan method will launch a specific adhoc device scan for Cisco IOS-XE Device
// This is one of the most important of Vulscano as it is responsible to launch a scan job on the Docker daemon and
// provide results for vulnerabilities found
// It takes an AdHocScanDevice struct as parameter and return the Scan Results or an error
func (d *CiscoIOSXEDevice) Scan(dev *AdHocScanDevice) (*ScanResults, error) {

	var sr ScanResults

	// We Generate a Scan Job ID from HashGen library
	jobID, errHash := hashgen.GenHash()
	if errHash != nil {
		logging.VulscanoLog(
			"error",
			"Error when generating hash: ", errHash.Error())
		return nil, errHash
	}

	// Set the Scan Job ID in ScanResults struct
	sr.ScanJobID = jobID

	var devList []map[string]string

	device := map[string]string{
		"hostname": dev.Hostname,
		"ip":       dev.IPAddress,
	}
	devList = append(devList, device)

	if errIniBuilder := BuildIni(jobID, devList, d.jovalURL); errIniBuilder != nil {
		return nil, errIniBuilder
	}
	err := LaunchJovalDocker(&sr, jobID)

	if err != nil {
		return nil, err
	}

	err = parseScanReport(&sr, jobID)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// parseScanReport handles parsing reports/JobID folder after a VA scan is done.
// It will look for .json files and parse the content for each to report found vulnerabilities
func parseScanReport(res *ScanResults, jobID string) (err error) {
	reportDir := filepath.FromSlash(datadiros.GetDataDir() + "/reports/" + jobID)
	var scanReport ScanReportFile

	if _, err := os.Stat(reportDir); !os.IsNotExist(err) {

		err = filepath.Walk(reportDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Printf("prevent panic by handling failure accessing a path %q: %v\n", path, err)
				return err
			}
			if !info.IsDir() {
				reportFile, err := os.Open(path)

				if err != nil {
					return fmt.Errorf("error while reading report file %v: %v", path, err)
				}
				// Defer Named return when closing report JSON file to capture any error
				defer func() {
					if errCloseReportFile := reportFile.Close(); err != nil {
						err = errCloseReportFile
					}
				}()

				err = json.NewDecoder(reportFile).Decode(&scanReport)

				if err != nil {
					return fmt.Errorf("error while parsing JSON report file: %v", err)
				}
				// vulnCount determines the number of vulnerabilities found in the report
				var vulnCount int

				// vulnMetaSlice is a slice of Cisco openVuln API vulnerabilities metdata
				var vulnMetaSlice []openvulnapi.VulnMetadata

				// Declare WaitGroup to send requests to openVuln API in parallel
				var wg sync.WaitGroup

				// We set a rate limit to throttle Goroutines querying openVuln API.
				// This is to overcome Cisco openVuln API rate limiting (10 calls / second)
				rateLimit := time.NewTicker(200 * time.Millisecond)

				// Count number of found vulnerabilities in report to determine Wait Group length
				for _, ruleResult := range scanReport.RuleResults {
					if ruleResult.RuleResult == "fail" {
						vulnCount++
					}
				}

				// Add the number of found of vulnerabilities to match the number of goroutines we're launching
				wg.Add(vulnCount)

				// Loop to search for found vulnerabilities in the scan report and fetch metadata for each
				// vulnerability in a goroutine
				for _, ruleResult := range scanReport.RuleResults {
					if ruleResult.RuleResult == "fail" {
						go func(r *ScanReportFileResult) {
							defer wg.Done()
							<-rateLimit.C
							vulnMeta, err := openvulnapi.GetVulnMetaData((*r).RuleIdentifier[0].ResultCiscoSA)
							if err == nil {
								vulnMetaSlice = append(vulnMetaSlice, (*vulnMeta)[0])
							} else {
								logging.VulscanoLog("warning",
									"error when fetching vulnerability metadata for:",
									(*r).RuleIdentifier[0].ResultCiscoSA, ":", err.Error())
							}

						}(ruleResult)

					}

				}
				wg.Wait()
				// Start mapping Report File into ScanResults struct
				(*res).VulnerabilitiesFoundDetails = &vulnMetaSlice
				(*res).TotalVulnerabilitiesFound = vulnCount

			}

			return nil
		})

		return nil
	} else {
		return fmt.Errorf("directory %v not found in Reports directory", jobID)
	}

}
