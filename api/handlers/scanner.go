package handlers

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lucabrasi83/vulscano/inventorymgr"
	"github.com/lucabrasi83/vulscano/rediscache"

	"github.com/lucabrasi83/vulscano/postgresdb"

	"github.com/lucabrasi83/vulscano/hashgen"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/openvulnapi"
)

// scannedDevices slice stores devices currently undergoing a Vulnerability Assessment
// in order to avoid repeated VA request for the same device
// var scannedDevices = make([]string, 0)

// DeviceScanner interface provides abstraction for multi-vendor scan.
// Implementation is for single device scan request
type DeviceScanner interface {
	Scan(dev *AdHocScanDevice, j *JwtClaim) (*ScanResults, error)
}

// NewCiscoScanDevice will instantiate a new Scan device instance struct based on the OS type
func NewCiscoScanDevice(os string) *CiscoScanDevice {
	switch os {
	case ciscoIOS:
		return &CiscoScanDevice{
			jovalURL:    "http://download.jovalcm.com/content/jca/cisco.ios.cve.oval.xml",
			openVulnURL: "https://api.cisco.com/security/advisories/ios.json?version=",
		}
	case ciscoIOSXE:
		return &CiscoScanDevice{
			jovalURL:    "http://download.jovalcm.com/content/jca/cisco.iosxe.cve.oval.xml",
			openVulnURL: "https://api.cisco.com/security/advisories/iosxe.json?version=",
		}
	}
	return nil
}

// LaunchAbstractVendorScan will launch vendor agnostic scan. abs type must satisfy DeviceScanner interface
func LaunchAbstractVendorScan(abs DeviceScanner, dev *AdHocScanDevice, j *JwtClaim) (*ScanResults, error) {
	scanRes, err := abs.Scan(dev, j)
	if err != nil {
		return nil, err
	}
	return scanRes, nil
}

// Scan method will launch a vulnerability scan for a single Cisco Device
// This is one of the most important of Vulscano as it is responsible to launch a scan job on the Docker daemon and
// provide results for vulnerabilities found
// It takes an AdHocScanDevice struct as parameter and return the Scan Results or an error
func (d *CiscoScanDevice) Scan(dev *AdHocScanDevice, j *JwtClaim) (*ScanResults, error) {

	// Constant for Job Scan Results
	const scanJobFailedRes = "FAILED"
	const scanJobSuccessRes = "SUCCESS"

	// Struct holding the scan job results
	var sr ScanResults

	// Set Initial Job Start/End time type
	reportScanJobStartTime, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	var reportScanJobEndTime time.Time
	successfulScannedDevName := make([]string, 0)
	successfulScannedDevIP := make([]net.IP, 0)
	var scanJobStatus string

	// We Generate a Scan Job ID from HashGen library
	jobID, errHash := hashgen.GenHash()
	if errHash != nil {
		logging.VulscanoLog(
			"error",
			"Error when generating hash: ", errHash.Error())

		return nil, errHash
	}

	// Execute functions to save scan job report in DB
	defer func() {

		if sr.ScanJobExecutingAgent == "" {
			sr.ScanJobExecutingAgent = "NA"
		}

		errJobInsertDB := scanJobReportDB(
			jobID,
			reportScanJobStartTime,
			reportScanJobEndTime,
			successfulScannedDevName,
			successfulScannedDevIP,
			scanJobStatus,
			j,
			sr.ScanJobExecutingAgent,
		)

		if errJobInsertDB != nil {
			logging.VulscanoLog(
				"error",
				"Failed to insert Scan Job report in DB for Job ID: ", jobID, "error: ", errJobInsertDB.Error())
		}
	}()

	// Check if ongoing VA for requested device. This is to avoid repeated VA for the same device
	if deviceBeingScanned := isDeviceBeingScanned(dev.IPAddress); !deviceBeingScanned {

		err := rediscache.CacheStore.LPushScannedDevicesIP(dev.IPAddress)
		if err != nil {
			return nil, fmt.Errorf("not able to build cache list of devices for %v with IP %v",
				dev.Hostname, dev.IPAddress)
		}
	} else {

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		scanJobStatus = scanJobFailedRes

		return nil, fmt.Errorf("there is already an ongoing VA for device %v with IP: %v",
			dev.Hostname, dev.IPAddress)
	}

	// Remove device from ongoing scan slice in defer function
	defer func() {
		removeDevicefromScannedDeviceSlice(dev.IPAddress)
	}()

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

	var sshGateway UserSSHGateway

	if dev.SSHGateway != "" {
		sshGatewayDB, errSSHGw := getUserSSHGatewayDetails(j.Enterprise, dev.SSHGateway)

		if errSSHGw != nil {

			reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

			scanJobStatus = scanJobFailedRes

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
		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		scanJobStatus = scanJobFailedRes

		return nil, errDevCredsDB
	}

	err := sendAgentScanRequest(jobID, devList, d.jovalURL, &sshGateway, devCreds, &sr, nil)

	if err != nil {

		reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		scanJobStatus = scanJobFailedRes

		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(1)

	// Fetch Vulnerabilities fixed versions in separate Goroutine
	go func() {
		defer wg.Done()

		// Exit Goroutine if no device version submitted from API consumer
		if dev.OSVersion == "" {
			return
		}

		vulnFixed, err := openvulnapi.GetVulnFixedVersions(
			d.openVulnURL,
			dev.OSVersion,
		)

		if err != nil {
			logging.VulscanoLog(
				"error",
				"Failed to fetch vulnerability fixed versions from openVulnAPI for Version: ",
				dev.OSVersion,
				" Error: ",
				err.Error(),
			)
			return
		}

		for _, vFixed := range vulnFixed {
			for idx, vFound := range sr.VulnerabilitiesFoundDetails {
				if vFixed.AdvisoryID == vFound.AdvisoryID {
					sr.VulnerabilitiesFoundDetails[idx].FixedVersions = vFixed.FixedVersions
				}
			}
		}

	}()

	// Set Scan Job End Time
	reportScanJobEndTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	sr.ScanJobEndTime = reportScanJobEndTime

	// Set Scan Job Report data if successful. This is will picked by the defer anonymous function
	scanJobStatus = scanJobSuccessRes
	successfulScannedDevName = append(successfulScannedDevName, dev.Hostname)
	successfulScannedDevIP = append(successfulScannedDevIP, net.ParseIP(dev.IPAddress).To4())

	wg.Wait()

	return &sr, nil
}

// AnutaInventoryScan is the main function to handle VA for devices part of Anuta NCX Inventory
func AnutaInventoryScan(d *AnutaDeviceScanRequest, j *JwtClaim) (*AnutaDeviceInventory, error) {

	anutaDev, errAnuta := inventorymgr.GetAnutaDevice(d.DeviceID)

	if errAnuta != nil {
		logging.VulscanoLog("error",
			"Error while fetching device inventory details from Anuta NCX: ", errAnuta.Error())
		return nil, errAnuta

	}

	// Don't waste resources trying to scan an offline device
	if anutaDev.Status != "ONLINE" {
		logging.VulscanoLog("error", "Anuta device "+anutaDev.DeviceName+
			" scan request aborted as device is currently marked as offline")

		return nil, fmt.Errorf("device %v currently marked as offline in Anuta inventory", anutaDev.DeviceName)

	}

	anutaScannedDev := AnutaDeviceInventory{
		DeviceName:    anutaDev.DeviceName,
		MgmtIPAddress: net.ParseIP(anutaDev.MgmtIPAddress).To4(),
		Status:        anutaDev.Status,
		OSType:        anutaDev.OSType,
		OSVersion:     anutaDev.OSVersion,
		CiscoModel:    anutaDev.CiscoModel,
		SerialNumber:  anutaDev.SerialNumber,
		Hostname:      anutaDev.Hostname,
		EnterpriseID:  strings.ToUpper(anutaDev.DeviceName[0:3]),
	}

	// Look for real IOS-XE Version from Anuta. This will help to query recommended IOSXE Versions
	// for vulnerability remediation
	if anutaDev.OSType == "IOSXE" {

		anutaScannedDev.OSType = ciscoIOSXE

		if anutaDev.RealIOSXEVersion.IOSXEVersionChildContainer != "" &&
			anutaDev.RealIOSXEVersion.IOSXEVersionChildContainer != "noSuchInstance" {

			// Put original IOSd version if noSuchInstance reported from CPE during Anuta SNMP collection
			anutaScannedDev.OSVersion = anutaDev.RealIOSXEVersion.IOSXEVersionChildContainer

		}

	}

	ads := AdHocScanDevice{
		Hostname:        anutaScannedDev.DeviceName,
		IPAddress:       anutaScannedDev.MgmtIPAddress.String(),
		OSType:          anutaScannedDev.OSType,
		OSVersion:       anutaScannedDev.OSVersion,
		SSHGateway:      d.SSHGateway,
		CredentialsName: d.CredentialsName,
	}

	// devScanner represents DeviceScanner interface. Depending on the OS Type given, we instantiate
	// with proper device vendor parameters
	var devScanner DeviceScanner

	switch ads.OSType {
	case ciscoIOSXE, ciscoIOS:
		devScanner = NewCiscoScanDevice(ads.OSType)
		//if devScanner == nil {
		//	return nil, fmt.Errorf("failed to instantiate Device with given OS Type %v", ads.OSType)
		//}
	default:
		return nil, fmt.Errorf("OS Type %v not supported for device %v",
			anutaScannedDev.OSType, anutaScannedDev.DeviceName)
	}

	// Launch Vulnerability Assessment
	scanRes, err := LaunchAbstractVendorScan(devScanner, &ads, j)

	if err != nil {
		return nil, err
	}

	anutaScannedDev.ScanResults = scanRes

	// Persist Vulnerability Assessment in DB
	err = deviceVAReportDB(&anutaScannedDev, scanRes)

	if err != nil {
		logging.VulscanoLog("error",
			"Error while inserting Device VA Report into DB: ", err.Error())
		return nil, err
	}

	return &anutaScannedDev, nil

}

// scanJobReportDB will interact with Postgres DB to insert the scan job info for analytics
func scanJobReportDB(j string,
	st time.Time,
	et time.Time,
	dn []string,
	di []net.IP,
	r string,
	jwt *JwtClaim,
	a string) error {

	errDB := postgresdb.DBInstance.PersistScanJobReport(j, st, et, dn, di, r, jwt.UserID, a)
	if errDB != nil {
		return errDB
	}
	return nil
}

// deviceVAReportDB handles DB interaction to persist VA Results when scanned is requested from an inventory source
func deviceVAReportDB(d *AnutaDeviceInventory, r *ScanResults) error {

	vulnFound := make([]string, 0, 20)

	for _, vuln := range r.VulnerabilitiesFoundDetails {
		vulnFound = append(vulnFound, vuln.AdvisoryID)
	}
	// Insert Device Vulnerability Assessment detailed results
	errDB := postgresdb.DBInstance.PersistDeviceVAJobReport(
		d.DeviceName,                  // Column device_id
		d.MgmtIPAddress,               // Column mgmt_ip_address
		r.ScanJobEndTime,              // Column last_successful_scan
		vulnFound,                     // Column vulnerabilities_found
		r.TotalVulnerabilitiesScanned, // Column total_vulnerabilities_scanned
		d.EnterpriseID,                // Column enterprise_id
		r.ScanDeviceMeanTime,          // Column scan_mean_time
		d.OSType,                      // Column os_type
		d.OSVersion,                   // Column os_version,
		d.CiscoModel,                  // Column device_model
		d.SerialNumber,                // Column serial_number
		d.Hostname,                    // Column device_hostname

	)

	if errDB != nil {
		return errDB
	}

	// Insert Device Vulnerability Assessment summary history record
	errDB = postgresdb.DBInstance.PersistDeviceVAHistory(
		d.DeviceName,     // Column device_id
		vulnFound,        // Column vuln_found
		r.ScanJobEndTime, // Column timestamp
	)

	if errDB != nil {
		return errDB
	}

	return nil
}

// isDeviceBeingScanned check if the device is currently undergoing a Vulnerability assessment
// It uses Sort package and binary search for efficiency
func isDeviceBeingScanned(d string) bool {
	cacheScannedDev, err := rediscache.CacheStore.LRangeScannedDevices()

	if err != nil {
		logging.VulscanoLog("error", "unable to get the list of current scanned device: ", err.Error())
	}

	sort.Strings(cacheScannedDev)
	i := sort.Search(len(cacheScannedDev),
		func(i int) bool { return cacheScannedDev[i] >= d })

	if i < len(cacheScannedDev) && cacheScannedDev[i] == d {
		return true
	}
	return false
}

// removeDeviceFromScannedDeviceSlice removes the device from scannedDevices slice
// The removal happens upon a call to Device VA Scan API endpoint and is executing after successful scan or
// whenever an error is returned from the Scan() method
func removeDevicefromScannedDeviceSlice(d string) {

	rediscache.CacheStore.LRemScannedDevicesIP(d)

}

// getUserSSHGatewayDetails will return the User SSH Gateway Details if one is specified
func getUserSSHGatewayDetails(entid string, gw string) (*UserSSHGateway, error) {

	sshGw, err := postgresdb.DBInstance.FetchUserSSHGateway(entid, gw)

	if err != nil {
		return nil, err
	}

	userSSHGw := &UserSSHGateway{
		GatewayName:       sshGw.GatewayName,
		GatewayIP:         sshGw.GatewayIP,
		GatewayUsername:   sshGw.GatewayUsername,
		GatewayPassword:   sshGw.GatewayPassword,
		GatewayPrivateKey: sshGw.GatewayPrivateKey,
	}

	if userSSHGw.GatewayPassword == "" && userSSHGw.GatewayPrivateKey == "" {
		return nil, fmt.Errorf("gateway %s has neither password nor SSH private key associated", userSSHGw.GatewayName)
	}

	return userSSHGw, nil
}

// getUserSSHGatewayDetails will return the User SSH Gateway Details if one is specified
func getUserDeviceCredentialsDetails(uid string, cn string) (*UserDeviceCredentials, error) {

	dbDeviceCreds, err := postgresdb.DBInstance.FetchDeviceCredentials(uid, cn)

	if err != nil {
		return nil, err
	}

	dCreds := &UserDeviceCredentials{
		CredentialsName:         dbDeviceCreds.CredentialsName,
		CredentialsDeviceVendor: strings.ToUpper(dbDeviceCreds.CredentialsDeviceVendor),
		Username:                dbDeviceCreds.Username,
		Password:                dbDeviceCreds.Password,
		PrivateKey:              dbDeviceCreds.PrivateKey,
		IOSEnablePassword:       dbDeviceCreds.IOSEnablePassword,
	}

	if dbDeviceCreds.Password == "" && dbDeviceCreds.PrivateKey == "" {
		return nil, fmt.Errorf("device credentials %s has neither password nor SSH private key associated",
			dCreds.CredentialsName)
	}

	return dCreds, nil
}
