package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lucabrasi83/vulscano/inventorymgr"
	"github.com/lucabrasi83/vulscano/rediscache"

	"github.com/lucabrasi83/vulscano/postgresdb"

	"github.com/lucabrasi83/vulscano/datadiros"
	"github.com/lucabrasi83/vulscano/hashgen"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/openvulnapi"
)

// DeviceScanner interface provides abstraction for multi-vendor scan.
// Implementation is for single device scan request
type DeviceBulkScanner interface {
	BulkScan(dev *AdHocBulkScan, j *JwtClaim) (*BulkScanResults, error)
}

// LaunchAbstractVendorBulkScan will launch vendor agnostic bulk scan. abs type must satisfy DeviceScanner interface
func LaunchAbstractVendorBulkScan(abs DeviceBulkScanner, dev *AdHocBulkScan, j *JwtClaim) (*BulkScanResults, error) {
	scanRes, err := abs.BulkScan(dev, j)
	if err != nil {
		return nil, err
	}
	return scanRes, nil
}

// BulkScan method will launch a vulnerability scan for multiple Cisco Devices
// This is one of the most important method of Vulscano as it is responsible to launch a scan job on the Docker daemon
// and provide results for vulnerabilities found
// It takes a slice of AdHocScanDevice struct as parameter and return the Scan Results or an error
func (d *CiscoScanDevice) BulkScan(dev *AdHocBulkScan, j *JwtClaim) (*BulkScanResults, error) {

	// Constant for Job Scan Results
	const scanJobFailedRes = "FAILED"
	const scanJobSuccessRes = "SUCCESS"

	// Set Initial Job Start/End time type
	reportScanJobStartTime, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	var reportScanJobEndTime time.Time
	successfulScannedDevName := make([]string, 0, bulkDevMaxLimit)
	successfulScannedDevIP := make([]net.IP, 0, bulkDevMaxLimit)
	currentJobOngoingScannedDevices := make([]string, 0, bulkDevMaxLimit)
	var scanJobStatus string

	// We Generate a Scan Job ID from HashGen library
	jobID, errHash := hashgen.GenHash()
	if errHash != nil {
		logging.VulscanoLog(
			"error",
			"Error when generating hash: ", errHash.Error())

		return nil, errHash
	}

	defer func() {
		errJobInsertDB := scanJobReportDB(
			jobID,
			reportScanJobStartTime,
			reportScanJobEndTime,
			successfulScannedDevName,
			successfulScannedDevIP,
			scanJobStatus,
			j)

		if errJobInsertDB != nil {
			logging.VulscanoLog(
				"error",
				"Failed to insert Scan Job report in DB for Job ID: ", jobID, "error: ", errJobInsertDB.Error())
		}
	}()

	for _, dv := range dev.Devices {

		// Check if ongoing VA for requested device. This is to avoid repeated VA for the same device
		if deviceBeingScanned := isDeviceBeingScanned(dv.IPAddress); !deviceBeingScanned {

			// muScannedDevice.Lock()
			// scannedDevices = append(scannedDevices, dv.IPAddress)
			err := rediscache.CacheStore.LPushScannedDevicesIP(dv.IPAddress)
			if err != nil {
				return nil, fmt.Errorf("not able to build cache list of devices for %v with IP %v",
					dv.Hostname, dv.IPAddress)
			}
			currentJobOngoingScannedDevices = append(currentJobOngoingScannedDevices, dv.IPAddress)
			// muScannedDevice.Unlock()
		} else {

			reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

			scanJobStatus = scanJobFailedRes

			// For Bulk Scan, make sure devices previously added as part of this job
			// are removed from ongoing Scanned device slice.
			if len(currentJobOngoingScannedDevices) > 0 {

				for _, ip := range currentJobOngoingScannedDevices {
					removeDevicefromScannedDeviceSlice(ip)
				}
			}
			reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

			scanJobStatus = scanJobFailedRes

			return nil, fmt.Errorf("there is already an ongoing VA for device %v with IP: %v",
				dv.Hostname, dv.IPAddress)
		}
	}

	// Remove device from ongoing scan slice in defer function
	defer func() {
		for _, dv := range dev.Devices {
			removeDevicefromScannedDeviceSlice(dv.IPAddress)
		}
	}()

	var sr BulkScanResults

	// Set the Scan Job ID in ScanResults struct
	sr.ScanJobID = jobID

	// Set the Scan Job Start Time
	sr.ScanJobStartTime = reportScanJobStartTime

	devList := make([]map[string]string, 0, bulkDevMaxLimit)

	for _, dv := range dev.Devices {
		device := map[string]string{
			"hostname": dv.Hostname,
			"ip":       dv.IPAddress,
		}
		devList = append(devList, device)
	}

	var sshGateway UserSSHGateway

	if dev.SSHGateway != "" {
		sshGatewayDB, errSSHGw := getUserSSHGatewayDetails(j.Enterprise, dev.SSHGateway)

		if errSSHGw != nil {
			return nil, errSSHGw
		}

		// Map SSHGateway DB struct to UserSSHGateway struct
		sshGateway.GatewayUsername = sshGatewayDB.GatewayUsername
		sshGateway.GatewayPassword = sshGatewayDB.GatewayPassword
		sshGateway.GatewayName = sshGatewayDB.GatewayName
		sshGateway.GatewayIP = sshGatewayDB.GatewayIP
		sshGateway.GatewayPrivateKey = sshGatewayDB.GatewayPrivateKey

	}

	// Get Device Credentials details and pass the ini file builder
	// No need to check if Credentials Name is empty as it is already validated by Gin Handler
	devCreds, errDevCredsDB := getUserDeviceCredentialsDetails(j.UserID, dev.CredentialsName)

	if errDevCredsDB != nil {
		return nil, errDevCredsDB
	}

	if errIniBuilder := BuildIni(jobID, devList, d.jovalURL, &sshGateway, devCreds); errIniBuilder != nil {

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		scanJobStatus = scanJobFailedRes

		return nil, errIniBuilder
	}

	err := LaunchJovalDocker(jobID)

	if err != nil {

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		scanJobStatus = scanJobFailedRes

		switch err {
		case context.DeadlineExceeded:
			return nil, fmt.Errorf("scan job %s did not complete within the timeout", jobID)
		default:
			return nil, err
		}

	}

	err = parseBulkScanReport(&sr, jobID)
	if err != nil {

		logging.VulscanoLog("error", err.Error())

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		scanJobStatus = scanJobFailedRes

		return nil, err
	}

	// Set Scan Job End Time
	reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	sr.ScanJobEndTime = reportScanJobEndTime

	// Set Scan Job Report data if successful. This is will picked by the defer anonymous function
	scanJobStatus = scanJobSuccessRes

	// Parse Scan Results to populate slices of devices successfully scanned Hostname and IP
	for _, dv := range sr.VulnerabilitiesFound {
		successfulScannedDevName = append(successfulScannedDevName, dv.DeviceName)
		sr.DevicesScannedSuccess = append(sr.DevicesScannedSuccess, dv.DeviceName)
		for _, ip := range dev.Devices {
			if dv.DeviceName == ip.Hostname {
				successfulScannedDevIP = append(successfulScannedDevIP, net.ParseIP(ip.IPAddress).To4())
			}
		}
	}

	return &sr, nil
}

// parseScanReport handles parsing reports/JobID folder after a VA scan is done.
// It will look for .json files and parse the content for each to report found vulnerabilities
func parseBulkScanReport(res *BulkScanResults, jobID string) (err error) {

	const jovalReportFoundTag = "fail"

	reportDir := filepath.FromSlash(datadiros.GetDataDir() + "/reports/" + jobID)
	var scanReport ScanReportFile

	if _, err := os.Stat(reportDir); !os.IsNotExist(err) {

		err = filepath.Walk(reportDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				logging.VulscanoLog("error",
					"unable to access Joval reports directory: ", path, "error: ", err,
				)
				//fmt.Printf("prevent panic by handling failure accessing a path %q: %v\n", path, err)
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
					return fmt.Errorf("error while parsing JSON report file %v for Job ID %v: %v", path, jobID, err)
				}
				// vulnCount determines the number of vulnerabilities found in the report
				var vulnCount int

				// vulnTotal determines the number of total vulnerabilities scanned
				vulnTotal := len(scanReport.RuleResults)

				// Verify that Joval JSON report rule_results array contains elements
				if vulnTotal > 0 {

					// duplicateSAMap tracks duplicates SA found in Joval Scan Report
					duplicateSAMap := map[string]bool{}

					// vulnMetaSlice is a slice of Cisco openVuln API vulnerabilities metadata
					vulnMetaSlice := make([]openvulnapi.VulnMetadata, 0)

					// Declare WaitGroup to send requests to openVuln API in parallel
					var wg sync.WaitGroup

					// We set a rate limit to throttle Goroutines querying DB for Vulnerabilities metadata.
					rateLimit := time.NewTicker(20 * time.Millisecond)

					defer rateLimit.Stop()

					// Count number of found vulnerabilities in report to determine Wait Group length
					// Update duplicateSAMap to find duplicated Cisco SA in Joval Report
					for _, ruleResult := range scanReport.RuleResults {

						if ruleResult.RuleResult == jovalReportFoundTag &&
							!duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] {
							duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] = true
							vulnCount++
						}
					}

					// Add the number of found of vulnerabilities to match the number of goroutines we're launching
					wg.Add(vulnCount)

					// Declare Mutex to prevent Race condition on vulnMetaSlice slice
					var mu sync.RWMutex

					// Reset duplicateSAMap
					duplicateSAMap = make(map[string]bool)

					// Loop to search for found vulnerabilities in the scan report and fetch metadata for each
					// vulnerability in a goroutine
					for _, ruleResult := range scanReport.RuleResults {
						if ruleResult.RuleResult == jovalReportFoundTag &&
							!duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] {
							duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] = true
							go func(r ScanReportFileResult) {
								defer wg.Done()
								<-rateLimit.C

								vulnMeta := postgresdb.DBInstance.FetchCiscoSAMeta(r.RuleIdentifier[0].ResultCiscoSA)

								// Exclusive access to vulnMetaSlice to prevent race condition
								mu.Lock()
								vulnMetaSlice = append(vulnMetaSlice, *vulnMeta)
								mu.Unlock()

							}(ruleResult)

						}

					}
					wg.Wait()

					// Format in type Time the Device Scan Mean Time from Joval JSON Report
					deviceScanStartTime, _ := time.Parse(time.RFC3339, scanReport.ScanStartTime)
					deviceScanEndTime, _ := time.Parse(time.RFC3339, scanReport.ScanEndTime)

					vulnFound := BulkScanVulnFound{
						DeviceName:                  scanReport.DeviceName,
						ScanDeviceMeanTime:          int(deviceScanEndTime.Sub(deviceScanStartTime).Seconds() * 1000),
						VulnerabilitiesFoundDetails: vulnMetaSlice,
						TotalVulnerabilitiesScanned: vulnTotal,
						TotalVulnerabilitiesFound:   vulnCount,
					}
					// Start mapping Report File into BulkScanResults struct
					res.VulnerabilitiesFound = append(res.VulnerabilitiesFound, vulnFound)
				} else {
					// Devices with empty rule_results JSON array were not successfully scanned
					// Append to the DevicesScannedFailure slice
					res.DevicesScannedFailure = append(res.DevicesScannedFailure, scanReport.DeviceName)
				}
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("error while parsing Joval Reports folder for Job ID %v recursively: %v", jobID, err)
		}

		return nil
	}
	return fmt.Errorf("directory %v not found in Reports directory", jobID)

}

// AnutaInventoryBulkScan is the main function to handle VA for multiple devices part of Anuta NCX Inventory
func AnutaInventoryBulkScan(d *AnutaDeviceBulkScanRequest, j *JwtClaim) (*AnutaBulkScanResults, error) {

	devCount := len(d.Devices)

	var wg sync.WaitGroup
	wg.Add(devCount)

	anutaScannedDevList := make([]AnutaDeviceInventory, 0)
	var skippedScannedDevices []string

	// We set a rate limit to throttle Goroutines querying Anuta.
	rateLimit := time.NewTicker(100 * time.Millisecond)

	defer rateLimit.Stop()

	for _, dev := range d.Devices {
		go func(dv string) {
			defer wg.Done()

			<-rateLimit.C

			anutaDev, err := inventorymgr.GetAnutaDevice(dv)
			if err != nil {
				logging.VulscanoLog("error",
					err.Error(),
				)
				skippedScannedDevices = append(skippedScannedDevices, dv)
				return
			}

			// Don't waste resources trying to scan an offline device
			if anutaDev.Status != "ONLINE" {
				logging.VulscanoLog("warning",
					"Skipping Anuta device "+anutaDev.DeviceName+" Scan Request as it is currently offline",
				)
				skippedScannedDevices = append(skippedScannedDevices, anutaDev.DeviceName)

				return
			}

			osType := anutaDev.OSType
			osVersion := anutaDev.OSVersion

			normalizeAnutaBulkDeviceOS(&osType, &osVersion, anutaDev)

			// Filter Devices if OS Type Requested is different than Device
			// This is to avoid false positive VA results and load the right OVAL definitions
			if osType != d.OSType {
				logging.VulscanoLog("warning",
					"Skipping Anuta device "+anutaDev.DeviceName+" Scan Request as OSType requested "+d.
						OSType+" does not match with device "+dv)

				skippedScannedDevices = append(skippedScannedDevices, anutaDev.DeviceName)

				return
			}

			anutaScannedDevList = append(anutaScannedDevList, AnutaDeviceInventory{
				DeviceName:    anutaDev.DeviceName,
				MgmtIPAddress: net.ParseIP(anutaDev.MgmtIPAddress).To4(),
				Status:        anutaDev.Status,
				OSType:        osType,
				OSVersion:     osVersion,
				CiscoModel:    anutaDev.CiscoModel,
				SerialNumber:  anutaDev.SerialNumber,
				Hostname:      anutaDev.Hostname,
				EnterpriseID:  strings.ToUpper(anutaDev.DeviceName[0:3]),
			})

		}(dev.DeviceID)
	}

	wg.Wait()

	if len(anutaScannedDevList) == 0 {
		return nil, fmt.Errorf("error: unable to find eligible device to scan from the ones provided")
	}

	adBulkScanList := make([]AdHocBulkScanDevice, 0)

	for _, d := range anutaScannedDevList {
		adBulkScanList = append(adBulkScanList, AdHocBulkScanDevice{
			Hostname:  d.DeviceName,
			IPAddress: d.MgmtIPAddress.String(),
		})
	}

	adBulkScanReq := &AdHocBulkScan{
		OSType:          d.OSType,
		SSHGateway:      d.SSHGateway,
		Devices:         adBulkScanList,
		CredentialsName: d.CredentialsName,
	}

	// devScanner represents DeviceScanner interface. Depending on the OS Type given, we instantiate
	// with proper device vendor parameters
	var devBulkScanner DeviceBulkScanner

	switch d.OSType {
	case ciscoIOSXE, ciscoIOS:
		devBulkScanner = NewCiscoScanDevice(d.OSType)
		//if devBulkScanner == nil {
		//	return nil, fmt.Errorf("failed to instantiate Device with given OS Type %v", d.OSType)
		//}
	default:
		return nil, fmt.Errorf("OS Type %v not supported", d.OSType)
	}

	// Launch Bulk Vulnerability Assessment
	scanRes, err := LaunchAbstractVendorBulkScan(devBulkScanner, adBulkScanReq, j)

	if err != nil {
		return nil, err
	}

	VABulkRes := mergeAnutaBulkScanResults(scanRes, anutaScannedDevList, skippedScannedDevices)

	// Persist Vulnerability Assessment in DB
	err = deviceBulkVAReportDB(VABulkRes)

	if err != nil {
		logging.VulscanoLog("error",
			"Error while inserting Device VA Report into DB: ", err.Error())
		return nil, err
	}

	return VABulkRes, nil

}

func normalizeAnutaBulkDeviceOS(osType *string, osVersion *string, adInv *inventorymgr.AnutaAPIDeviceDetails) {

	if adInv.OSType == "IOSXE" {

		*osType = ciscoIOSXE

		// Look for real IOS-XE Version from Anuta. This will help to query recommended IOSXE Versions
		// for vulnerability remediation
		*osVersion = adInv.OSVersion

		if adInv.RealIOSXEVersion.IOSXEVersionChildContainer != "" && adInv.RealIOSXEVersion.
			IOSXEVersionChildContainer != "noSuchInstance" {

			// Put original IOSd version if noSuchInstance reported from CPE during Anuta SNMP collection
			*osVersion = adInv.RealIOSXEVersion.IOSXEVersionChildContainer

		}

	}

}

func mergeAnutaBulkScanResults(r *BulkScanResults, d []AnutaDeviceInventory, s []string) *AnutaBulkScanResults {

	var anutaBulkRes AnutaBulkScanResults

	// Map Scan Job Summay Data
	anutaBulkRes.ScanJobID = r.ScanJobID
	anutaBulkRes.ScanJobStartTime = r.ScanJobStartTime
	anutaBulkRes.ScanJobEndTime = r.ScanJobEndTime
	anutaBulkRes.DevicesScannedFailure = r.DevicesScannedFailure
	anutaBulkRes.DevicesScannedSuccess = r.DevicesScannedSuccess

	if len(s) > 0 {
		anutaBulkRes.DevicesScannedSkipped = s
	}

	for _, dev := range d {

		for _, res := range r.VulnerabilitiesFound {

			if dev.DeviceName == res.DeviceName {
				anutaBulkRes.DevicesScanResults = append(
					anutaBulkRes.DevicesScanResults,
					AnutaBulkScanResultsChild{
						DeviceName:                  dev.DeviceName,
						MgmtIPAddress:               dev.MgmtIPAddress,
						Status:                      dev.Status,
						OSType:                      dev.OSType,
						OSVersion:                   dev.OSVersion,
						CiscoModel:                  dev.CiscoModel,
						SerialNumber:                dev.SerialNumber,
						Hostname:                    dev.Hostname,
						RecommendedSW:               dev.RecommendedSW,
						TotalVulnerabilitiesFound:   res.TotalVulnerabilitiesFound,
						TotalVulnerabilitiesScanned: res.TotalVulnerabilitiesScanned,
						ScanDeviceMeanTime:          res.ScanDeviceMeanTime,
						VulnerabilitiesFoundDetails: res.VulnerabilitiesFoundDetails,
						EnterpriseID:                dev.EnterpriseID,
					},
				)

			}

		}

	}

	return &anutaBulkRes

}

// deviceVAReportDB handles DB interaction to persist VA Results when scanned is requested from an inventory source
func deviceBulkVAReportDB(res *AnutaBulkScanResults) error {

	scanResSlice := make([]map[string]interface{}, 0)

	for _, vuln := range res.DevicesScanResults {

		vulnFound := make([]string, 0)

		for _, v := range vuln.VulnerabilitiesFoundDetails {

			vulnFound = append(vulnFound, v.AdvisoryID)
		}

		scanResMap := map[string]interface{}{
			"deviceName":       vuln.DeviceName,                  // Column device_id
			"deviceIP":         vuln.MgmtIPAddress,               // Column mgmt_ip_address
			"lastScan":         res.ScanJobEndTime,               // Column last_successful_scan
			"advisoryID":       vulnFound,                        // Column vulnerabilities_found
			"totalVulnScanned": vuln.TotalVulnerabilitiesScanned, // Column total_vulnerabilities_scanned
			"enterpriseID":     vuln.EnterpriseID,                // Column enterprise_id
			"scanMeantime":     vuln.ScanDeviceMeanTime,          // Column scan_mean_time
			"osType":           vuln.OSType,                      // Column os_type
			"osVersion":        vuln.OSVersion,                   // Column os_version
			"deviceModel":      vuln.CiscoModel,                  // Column device_model
			"serialNumber":     vuln.SerialNumber,                // Column serial_number
			"deviceHostname":   vuln.Hostname,                    // Column device_hostname
		}

		scanResSlice = append(scanResSlice, scanResMap)

	}

	errDB := postgresdb.DBInstance.PersistBulkDeviceVAReport(scanResSlice)

	if errDB != nil {
		return errDB
	}

	// Insert Device Vulnerability Assessment summary history record
	errDB = postgresdb.DBInstance.PersistBulkDeviceVAHistory(scanResSlice)

	if errDB != nil {
		return errDB
	}

	return nil
}
