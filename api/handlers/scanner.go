package handlers

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/lucabrasi83/vulscano/inventoryanuta"

	"github.com/lucabrasi83/vulscano/postgresdb"

	"github.com/gin-gonic/gin/json"
	"github.com/lucabrasi83/vulscano/datadiros"
	"github.com/lucabrasi83/vulscano/hashgen"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/openvulnapi"
)

var scannedDevices []string

type CiscoIOSXEDevice struct {
	jovalURL string
}

type CiscoIOSDevice struct {
	jovalURL string
}

type ScanResults struct {
	ScanJobID                   string                      `json:"scanJobID"`
	ScanJobStartTime            time.Time                   `json:"scanJobStartTime"`
	ScanJobEndTime              time.Time                   `json:"scanJobEndTime"`
	ScanDeviceMeanTime          string                      `json:"scanJobDeviceMeanTime"`
	TotalVulnerabilitiesFound   int                         `json:"totalVulnerabilitiesFound"`
	TotalVulnerabilitiesScanned int                         `json:"totalVulnerabilitiesScanned"`
	VulnerabilitiesFoundDetails *[]openvulnapi.VulnMetadata `json:"vulnerabilitiesFoundDetails"`
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

// TODO: Create Scanner interface type to better abstract multi-vendor VA Scans
type Scanner interface {
	Scan()
}

func newCiscoIOSXEDevice() *CiscoIOSXEDevice {
	d := CiscoIOSXEDevice{
		jovalURL: "http://download.jovalcm.com/content/cisco.iosxe.cve.oval.xml",
	}
	return &d
}
func newCiscoIOSDevice() *CiscoIOSDevice {
	d := CiscoIOSDevice{
		jovalURL: "http://download.jovalcm.com/content/cisco.ios.cve.oval.xml",
	}
	return &d
}

// Scan method will launch a specific adhoc device scan for Cisco IOS-XE Device
// This is one of the most important of Vulscano as it is responsible to launch a scan job on the Docker daemon and
// provide results for vulnerabilities found
// It takes an AdHocScanDevice struct as parameter and return the Scan Results or an error
func (d *CiscoIOSXEDevice) Scan(dev *AdHocScanDevice, j *JwtClaim) (*ScanResults, error) {

	// Set Initial Job Start/End time type
	reportScanJobStartTime, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	var reportScanJobEndTime time.Time

	// We Generate a Scan Job ID from HashGen library
	jobID, errHash := hashgen.GenHash()
	if errHash != nil {
		logging.VulscanoLog(
			"error",
			"Error when generating hash: ", errHash.Error())

		return nil, errHash
	}

	// Mutex for scannedDevices slice to prevent race condition
	var muScannedDevice sync.Mutex

	// Check if ongoing VA for requested device. This is to avoid repeated VA for the same device
	if deviceBeingScanned := isDeviceBeingScanned(dev.IPAddress); !deviceBeingScanned {

		muScannedDevice.Lock()
		scannedDevices = append(scannedDevices, dev.IPAddress)
		muScannedDevice.Unlock()
	} else {

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		errJobInsertDB := scanJobReportDB(
			jobID,
			reportScanJobStartTime,
			reportScanJobEndTime,
			[]string{dev.Hostname},
			[]net.IP{net.ParseIP(dev.IPAddress).To4()},
			"FAILED",
			j)

		if errJobInsertDB != nil {
			logging.VulscanoLog(
				"error",
				"Failed to insert Scan Job report in DB for Job ID: ", jobID, errJobInsertDB.Error())
		}

		return nil, fmt.Errorf("there is already an ongoing VA for device %v with IP: %v",
			dev.Hostname, dev.IPAddress)
	}

	var sr ScanResults

	// Set the Scan Job ID in ScanResults struct
	sr.ScanJobID = jobID

	// Set the Scan Job Start Time
	sr.ScanJobStartTime = reportScanJobStartTime

	var devList []map[string]string

	device := map[string]string{
		"hostname": dev.Hostname,
		"ip":       dev.IPAddress,
	}
	devList = append(devList, device)

	if errIniBuilder := BuildIni(jobID, devList, d.jovalURL); errIniBuilder != nil {

		removeDevicefromScannedDeviceSlice(dev.IPAddress)

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		errJobInsertDB := scanJobReportDB(
			jobID,
			reportScanJobStartTime,
			reportScanJobEndTime,
			[]string{dev.Hostname},
			[]net.IP{net.ParseIP(dev.IPAddress).To4()},
			"FAILED",
			j)

		if errJobInsertDB != nil {
			logging.VulscanoLog(
				"error",
				"Failed to insert Scan Job report in DB for Job ID: ", jobID, errJobInsertDB.Error())
		}
		return nil, errIniBuilder
	}
	err := LaunchJovalDocker(&sr, jobID)

	if err != nil {
		removeDevicefromScannedDeviceSlice(dev.IPAddress)

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		errJobInsertDB := scanJobReportDB(
			jobID,
			reportScanJobStartTime,
			reportScanJobEndTime,
			[]string{dev.Hostname},
			[]net.IP{net.ParseIP(dev.IPAddress).To4()},
			"FAILED",
			j)

		if errJobInsertDB != nil {
			logging.VulscanoLog(
				"error",
				"Failed to insert Scan Job report in DB for Job ID: ", jobID, errJobInsertDB.Error())
		}
		return nil, err
	}

	err = parseScanReport(&sr, jobID)
	if err != nil {

		removeDevicefromScannedDeviceSlice(dev.IPAddress)

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		errJobInsertDB := scanJobReportDB(
			jobID,
			reportScanJobStartTime,
			reportScanJobEndTime,
			[]string{dev.Hostname},
			[]net.IP{net.ParseIP(dev.IPAddress).To4()},
			"FAILED",
			j)

		if errJobInsertDB != nil {
			logging.VulscanoLog(
				"error",
				"Failed to insert Scan Job report in DB for Job ID: ", jobID, errJobInsertDB.Error())
		}
		return nil, err
	}

	removeDevicefromScannedDeviceSlice(dev.IPAddress)

	// Set Scan Job End Time
	reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	sr.ScanJobEndTime = reportScanJobEndTime

	errJobInsertDB := scanJobReportDB(
		jobID,
		reportScanJobStartTime,
		reportScanJobEndTime,
		[]string{dev.Hostname},
		[]net.IP{net.ParseIP(dev.IPAddress).To4()},
		"SUCCESS",
		j)

	if errJobInsertDB != nil {
		logging.VulscanoLog(
			"error",
			"Failed to insert Scan Job report in DB for Job ID: ", jobID, errJobInsertDB.Error())
		return nil, errJobInsertDB
	}

	return &sr, nil
}

// Scan method will launch a specific adhoc device scan for Cisco IOS Device
// This is one of the most important of Vulscano as it is responsible to launch a scan job on the Docker daemon and
// provide results for vulnerabilities found
// It takes an AdHocScanDevice struct as parameter and return the Scan Results or an error
func (d *CiscoIOSDevice) Scan(dev *AdHocScanDevice, j *JwtClaim) (*ScanResults, error) {

	// Set Initial Job Start/End time type
	reportScanJobStartTime, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	var reportScanJobEndTime time.Time

	// We Generate a Scan Job ID from HashGen library
	jobID, errHash := hashgen.GenHash()
	if errHash != nil {
		logging.VulscanoLog(
			"error",
			"Error when generating hash: ", errHash.Error())

		return nil, errHash
	}

	// Mutex for scannedDevices slice to prevent race condition
	var muScannedDevice sync.Mutex

	// Check if ongoing VA for requested device. This is to avoid repeated VA for the same device
	if deviceBeingScanned := isDeviceBeingScanned(dev.IPAddress); !deviceBeingScanned {

		muScannedDevice.Lock()
		scannedDevices = append(scannedDevices, dev.IPAddress)
		muScannedDevice.Unlock()
	} else {

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		errJobInsertDB := scanJobReportDB(
			jobID,
			reportScanJobStartTime,
			reportScanJobEndTime,
			[]string{dev.Hostname},
			[]net.IP{net.ParseIP(dev.IPAddress).To4()},
			"FAILED",
			j)

		if errJobInsertDB != nil {
			logging.VulscanoLog(
				"error",
				"Failed to insert Scan Job report in DB for Job ID: ", jobID, errJobInsertDB.Error())
		}

		return nil, fmt.Errorf("there is already an ongoing VA for device %v with IP: %v",
			dev.Hostname, dev.IPAddress)
	}

	var sr ScanResults

	// Set the Scan Job ID in ScanResults struct
	sr.ScanJobID = jobID

	// Set the Scan Job Start Time
	sr.ScanJobStartTime = reportScanJobStartTime

	var devList []map[string]string

	device := map[string]string{
		"hostname": dev.Hostname,
		"ip":       dev.IPAddress,
	}

	// devList is used to build the Joval INI file in case multiple devices to be scanned in same container
	devList = append(devList, device)

	if errIniBuilder := BuildIni(jobID, devList, d.jovalURL); errIniBuilder != nil {

		removeDevicefromScannedDeviceSlice(dev.IPAddress)

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		errJobInsertDB := scanJobReportDB(
			jobID,
			reportScanJobStartTime,
			reportScanJobEndTime,
			[]string{dev.Hostname},
			[]net.IP{net.ParseIP(dev.IPAddress).To4()},
			"FAILED",
			j)

		if errJobInsertDB != nil {
			logging.VulscanoLog(
				"error",
				"Failed to insert Scan Job report in DB for Job ID: ", jobID, errJobInsertDB.Error())
		}
		return nil, errIniBuilder
	}
	err := LaunchJovalDocker(&sr, jobID)

	if err != nil {

		removeDevicefromScannedDeviceSlice(dev.IPAddress)

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		errJobInsertDB := scanJobReportDB(
			jobID,
			reportScanJobStartTime,
			reportScanJobEndTime,
			[]string{dev.Hostname},
			[]net.IP{net.ParseIP(dev.IPAddress).To4()},
			"FAILED",
			j)

		if errJobInsertDB != nil {
			logging.VulscanoLog(
				"error",
				"Failed to insert Scan Job report in DB for Job ID: ", jobID, errJobInsertDB.Error())
		}

		return nil, err
	}

	err = parseScanReport(&sr, jobID)
	if err != nil {
		removeDevicefromScannedDeviceSlice(dev.IPAddress)

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		errJobInsertDB := scanJobReportDB(
			jobID,
			reportScanJobStartTime,
			reportScanJobEndTime,
			[]string{dev.Hostname},
			[]net.IP{net.ParseIP(dev.IPAddress).To4()},
			"FAILED",
			j)

		if errJobInsertDB != nil {
			logging.VulscanoLog(
				"error",
				"Failed to insert Scan Job report in DB for Job ID: ", jobID, errJobInsertDB.Error())
		}
		return nil, err
	}
	removeDevicefromScannedDeviceSlice(dev.IPAddress)

	// Set Scan Job End Time
	reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	sr.ScanJobEndTime = reportScanJobEndTime

	errJobInsertDB := scanJobReportDB(
		jobID,
		reportScanJobStartTime,
		reportScanJobEndTime,
		[]string{dev.Hostname},
		[]net.IP{net.ParseIP(dev.IPAddress).To4()},
		"SUCCESS",
		j)

	if errJobInsertDB != nil {
		logging.VulscanoLog(
			"error",
			"Failed to insert Scan Job report in DB for Job ID: ", jobID, errJobInsertDB.Error())
		return nil, errJobInsertDB
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

				// vulnTotal determines the number of total vulnerabilities scanned
				vulnTotal := len(scanReport.RuleResults)

				// duplicateSAMap tracks duplicates SA found in Joval Scan Report
				duplicateSAMap := map[string]bool{}

				// vulnMetaSlice is a slice of Cisco openVuln API vulnerabilities metadata
				var vulnMetaSlice []openvulnapi.VulnMetadata

				// Declare WaitGroup to send requests to openVuln API in parallel
				var wg sync.WaitGroup

				// We set a rate limit to throttle Goroutines querying DB for Vulnerabilities metadata.
				rateLimit := time.NewTicker(20 * time.Millisecond)

				// Count number of found vulnerabilities in report to determine Wait Group length
				// Update duplicateSAMap to find duplicated Cisco SA in Joval Report
				for _, ruleResult := range scanReport.RuleResults {

					if ruleResult.RuleResult == "fail" && !duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] {
						duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] = true
						vulnCount++
					}
				}

				// Add the number of found of vulnerabilities to match the number of goroutines we're launching
				wg.Add(vulnCount)

				// Declare Mutex to prevent Race condition on vulnMetaSlice slice
				var mu sync.Mutex

				// Reset duplicateSAMap
				duplicateSAMap = make(map[string]bool)

				// Loop to search for found vulnerabilities in the scan report and fetch metadata for each
				// vulnerability in a goroutine
				for _, ruleResult := range scanReport.RuleResults {
					if ruleResult.RuleResult == "fail" && !duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] {
						duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] = true
						go func(r *ScanReportFileResult) {
							defer wg.Done()
							<-rateLimit.C

							vulnMeta := postgresdb.DBInstance.FetchCiscoSAMeta((*r).RuleIdentifier[0].ResultCiscoSA)

							// Exclusive access to vulnMetaSlice to prevent race condition
							mu.Lock()
							vulnMetaSlice = append(vulnMetaSlice, *vulnMeta)
							mu.Unlock()

						}(ruleResult)

					}

				}
				wg.Wait()
				// Start mapping Report File into ScanResults struct
				(*res).VulnerabilitiesFoundDetails = &vulnMetaSlice
				(*res).TotalVulnerabilitiesFound = vulnCount
				(*res).TotalVulnerabilitiesScanned = vulnTotal

			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("error while parsing Reports folder recursively: %v", err)
		}

		return nil
	}
	return fmt.Errorf("directory %v not found in Reports directory", jobID)

}

// AnutaInventoryScan is the main function to handle VA for devices part of Anuta NCX Inventory
func AnutaInventoryScan(d *AnutaDeviceScanRequest, j *JwtClaim) (*AnutaDeviceInventory, *ScanResults, error) {

	anutaDev, errAnuta := inventoryanuta.GetAnutaDevice((*d).DeviceID)

	if errAnuta != nil {
		logging.VulscanoLog("error",
			"Error while fetching device inventory details from Anuta NCX: ", errAnuta.Error())
		return nil, nil, errAnuta

	}

	anutaScannedDev := AnutaDeviceInventory{
		DeviceName:    anutaDev.DeviceName,
		MgmtIPAddress: net.ParseIP(anutaDev.MgmtIPAddress).To4(),
		Status:        anutaDev.Status,
		OSType:        anutaDev.OSType,
		OSVersion:     anutaDev.OSVersion,
		CiscoModel:    anutaDev.CiscoModel,
		EnterpriseID:  string(anutaDev.DeviceName[0:3]),
	}

	// Look for real IOS-XE Version from Anuta. This will help to query recommended IOSXE Versions
	// for vulnerability remediation
	if (*anutaDev).OSType == "IOSXE" && (*anutaDev).RealIOSXEVersion.IOSXEVersionChildContainer != "" {
		anutaScannedDev.OSVersion = (*anutaDev).RealIOSXEVersion.IOSXEVersionChildContainer
		anutaScannedDev.OSType = "IOS-XE"
	}

	ads := AdHocScanDevice{
		Hostname:  anutaScannedDev.DeviceName,
		IPAddress: anutaScannedDev.MgmtIPAddress.String(),
		OSType:    anutaScannedDev.OSType,
	}

	switch ads.OSType {
	case "IOS-XE":
		d := newCiscoIOSXEDevice()
		scanRes, err := d.Scan(&ads, j)
		if err != nil {

			return nil, nil, err
		}

		err = deviceVAReportDB(&anutaScannedDev, scanRes, j)

		if err != nil {
			logging.VulscanoLog("error",
				"Error while inserting Device VA Report into DB: ", err.Error())
			return nil, nil, err
		}

		return &anutaScannedDev, scanRes, nil

	case "IOS":
		d := newCiscoIOSDevice()
		scanRes, err := d.Scan(&ads, j)
		if err != nil {

			return nil, nil, err
		}

		err = deviceVAReportDB(&anutaScannedDev, scanRes, j)

		if err != nil {
			logging.VulscanoLog("error",
				"Error while inserting Device VA Report into DB: ", err.Error())
			return nil, nil, err
		}

		return &anutaScannedDev, scanRes, nil
	}

	return nil, nil, fmt.Errorf("OS Type %v not supported for device %v",
		anutaScannedDev.OSType, anutaScannedDev.DeviceName)

}

// scanJobReportDB will interact with Postgres DB to insert the scan job info for analytics
func scanJobReportDB(j string, st time.Time, et time.Time, dn []string, di []net.IP, r string, jwt *JwtClaim) error {

	errDB := postgresdb.DBInstance.PersistScanJobReport(j, st, et, dn, di, r, (*jwt).UserID)
	if errDB != nil {
		return errDB
	}
	return nil
}

// deviceVAReportDB handles DB interaction to persist VA Results when scanned is requested from an inventory source
func deviceVAReportDB(d *AnutaDeviceInventory, r *ScanResults, j *JwtClaim) error {

	var vulnFound []string

	for _, vuln := range *r.VulnerabilitiesFoundDetails {
		vulnFound = append(vulnFound, vuln.AdvisoryID)
	}

	// Convert Device Scan Mean time to int to comply with Postgres column type
	deviceScanMeanTimeStripms := string((*r).ScanDeviceMeanTime[:len((*r).ScanDeviceMeanTime)-2])
	deviceScanMeanTime, errMeanTimeConv := strconv.Atoi(deviceScanMeanTimeStripms)

	if errMeanTimeConv != nil {
		logging.VulscanoLog("error",
			"Failed to convert Device Scan Mean Time for Job ID ", (*r).ScanJobID,
			"Raw value: ", (*r).ScanDeviceMeanTime, errMeanTimeConv.Error())
	}

	errDB := postgresdb.DBInstance.PersistDeviceVAJobReport(
		(*d).DeviceName,                  // Column device_id
		(*d).MgmtIPAddress,               // Column mgmt_ip_address
		(*r).ScanJobEndTime,              // Column last_successful_scan
		vulnFound,                        // Column vulnerabilities_found
		(*r).TotalVulnerabilitiesScanned, // Column total_vulnerabilities_scanned
		(*j).Enterprise,                  // Column enterprise_id
		deviceScanMeanTime,               // Column scan_mean_time
		(*d).OSType,                      // Column os_type
		(*d).OSVersion,                   // Column os_version,
		(*d).CiscoModel,                  // Column device_model
	)

	if errDB != nil {
		return errDB
	}
	return nil
}

// isDeviceBeingScanned check if the device is currently undergoing a Vulnerability assessment
// It uses Sort package and binary search for efficiency
func isDeviceBeingScanned(d string) bool {
	sort.Strings(scannedDevices)
	i := sort.Search(len(scannedDevices),
		func(i int) bool { return scannedDevices[i] >= d })

	if i < len(scannedDevices) && scannedDevices[i] == d {
		return true
	}
	return false
}

// removeDeviceFromScannedDeviceSlice is a helper function to remove the device from scannedDevices slice
// The removal happens upon a call to on-demand-scan API endpoint and is executing after successful scan or
// whenever an error is returned from the Scan() method
func removeDevicefromScannedDeviceSlice(d string) {

	// Mutex for scannedDevices slice to prevent race condition
	var muScannedDevices sync.Mutex

	sort.Strings(scannedDevices)
	i := sort.Search(len(scannedDevices),
		func(i int) bool { return scannedDevices[i] >= d })

	muScannedDevices.Lock()
	scannedDevices = append(scannedDevices[:i], scannedDevices[i+1:]...)
	muScannedDevices.Unlock()
}
