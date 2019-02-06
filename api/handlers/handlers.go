package handlers

import (
	"fmt"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/lucabrasi83/vulscano/initializer"
	"github.com/lucabrasi83/vulscano/openvulnapi"

	"github.com/appleboy/gin-jwt"

	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/postgresdb"
)

const (
	rootRole   = "vulscanoroot"
	rootUser   = "root@vulscano.com"
	userRole   = "vulscanouser"
	ciscoIOSXE = "IOS-XE"
	ciscoIOS   = "IOS"
)

// LaunchAdHocScan handler is the API endpoint to trigger a single device ad-hoc VA scan on the passed JSON body.
// The JSON body should be formatted as per below example:
func LaunchAdHocScan(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}
	// ads represents struct for AdHocScanDevice body sent by API consumer
	var ads AdHocScanDevice

	// devScanner represents DeviceScanner interface. Depending on the OS Type given, we instantiate
	// with proper device vendor parameters
	var devScanner DeviceScanner

	if err := c.ShouldBindJSON(&ads); err != nil {
		logging.VulscanoLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	switch ads.OSType {
	case ciscoIOSXE, ciscoIOS:
		devScanner = NewCiscoScanDevice(ads.OSType)
		if devScanner == nil {
			logging.VulscanoLog("error: ", "Failed to instantiate Device with given OS Type: ", ads.OSType)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to instantiate Device with given OS Type",
			})
			return
		}

	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Incorrect osType provided. Only IOS or IOS-XE supported",
		})
		return
	}

	scanRes, err := LaunchAbstractVendorScan(devScanner, &ads, &jwtClaim)
	if err != nil {
		logging.VulscanoLog("error: ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"results": *scanRes,
	})
}

// UpdateCiscoOpenVulnSAAll will pull all the published Cisco Security Advisories from openVuln API
// These will then be persisted in the database
// API Call doesn't require any payload in the body
func UpdateCiscoOpenVulnSAAll(c *gin.Context) {
	err := postgresdb.DBInstance.InsertAllCiscoAdvisories()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": "Cisco published security advisories successfully fetched and merged in DB.",
	})
}

// LaunchAnutaInventoryScan handler is the API endpoint to trigger an VA scan for a device part of Anuta NCX inventory.
func LaunchAnutaInventoryScan(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	var invDevice AnutaDeviceScanRequest

	if err := c.ShouldBindJSON(&invDevice); err != nil {
		logging.VulscanoLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Control to verify user Enterprise ID corresponds to Device trigram
	if entID, ok := jwtMapClaim["enterprise"].(string); ok &&
		(entID == invDevice.DeviceID[0:3]) || isUserVulscanoRoot(jwtMapClaim) {

		jwtClaim := JwtClaim{
			Enterprise: jwtMapClaim["enterprise"].(string),
			UserID:     jwtMapClaim["userID"].(string),
			Email:      jwtMapClaim["email"].(string),
			Role:       jwtMapClaim["role"].(string),
		}

		devRes, errAnutaAPI := AnutaInventoryScan(&invDevice, &jwtClaim)

		if errAnutaAPI != nil {

			c.JSON(http.StatusBadRequest, gin.H{
				"error": errAnutaAPI.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"deviceDetails": *devRes})
		return
	}

	c.JSON(http.StatusUnauthorized,
		gin.H{"error": "You're not allowed to run a Vulnerability Assessment on this device."})

}

func isUserVulscanoRoot(jwtMapClaim map[string]interface{}) bool {
	if role, ok := jwtMapClaim["role"].(string); ok && role == rootRole {
		return true
	}
	return false
}

// Ping is a health check status handler of the Vulscano API
// @Summary Ping Health Check
// @Description Verify the API is responding to HTTP requests
// @Accept  json
// @Produce  json
// @Success 200 {object} handlers.PingAPIResponse
// @Router /ping [get]
func Ping(c *gin.Context) {

	pingRes := PingAPIResponse{
		ReplyBack:       "pong",
		VulscanoVersion: initializer.Version,
		GolangVersion:   runtime.Version(),
	}

	c.JSON(http.StatusOK, pingRes)
}

func GetCurrentlyScannedDevices(c *gin.Context) {

	c.JSON(http.StatusOK, gin.H{
		"deviceCount": len(scannedDevices),
		"devicesIP":   scannedDevices,
	})

}

func GetAllUsers(c *gin.Context) {
	users, err := postgresdb.DBInstance.FetchAllUsers()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to fetch users from database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": *users})
}

func GetUser(c *gin.Context) {
	userInput := c.Param("user-id")

	userFound, err := postgresdb.DBInstance.FetchUser(userInput)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot find requested user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": *userFound})
}

func CreateUser(c *gin.Context) {

	var newUser VulscanoUserCreate

	if err := c.ShouldBindJSON(&newUser); err != nil {
		logging.VulscanoLog("error", "User creation request failed: ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !validateEmail(newUser.Email) || len(newUser.Email) > 60 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Email Address given. Note: " +
			"maximum of 60 characters allowed for this field."})
		return
	}
	if !validatePassword(newUser.Password) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Password given does not meet minimum length/complexity requirements",
		})
		return
	}
	if strings.ToLower(newUser.Role) != rootRole && strings.ToLower(newUser.Role) != userRole {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Only vulscanoroot and vulscanouser are possible values for the user role",
		})
		return
	}

	err := postgresdb.DBInstance.InsertNewUser(
		strings.ToLower(newUser.Email),
		newUser.Password,
		strings.ToUpper(newUser.Enterprise),
		strings.ToLower(newUser.Role))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": strings.ToLower(newUser.Email) + " user successfully created"})

}

func UpdateUser(c *gin.Context) {

	var updateUser VulscanoUserPatch
	user := c.Param("user-id")

	if err := c.ShouldBindJSON(&updateUser); err != nil {
		logging.VulscanoLog("error", "user update request failed: ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if updateUser.Enterprise == "" && updateUser.Role == "" && updateUser.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no value provided"})
		return
	}

	if isDBUser := postgresdb.DBInstance.AssertUserExists(user); !isDBUser {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user " + user + " does not exist"})
		return
	}

	if updateUser.Password != "" && !validatePassword(updateUser.Password) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Password given does not meet minimum length/complexity requirements",
		})
		return
	}

	if strings.ToLower(user) == rootUser && strings.ToLower(updateUser.Role) != "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "update of root user role is not allowed",
		})
		return
	}
	if updateUser.Role != "" && strings.ToLower(updateUser.Role) != rootRole && strings.ToLower(updateUser.
		Role) != userRole {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Only vulscanoroot and vulscanouser are possible values for the user role",
		})
		return
	}
	err := postgresdb.DBInstance.PatchUser(user, updateUser.Role, updateUser.Password, updateUser.Enterprise)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "user updated failed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": "user " + user + " successfully updated"})
}

func DeleteUser(c *gin.Context) {
	user := c.Param("user-id")

	if user == rootUser {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete root user"})
		return
	}

	if isDBUser := postgresdb.DBInstance.AssertUserExists(user); !isDBUser {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user " + user + " does not exist"})
		return
	}

	err := postgresdb.DBInstance.DeleteUser(user)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "user " + user + " deleted"})

}

func AdminGetSAVulnAffectingDevice(c *gin.Context) {

	vuln := c.Param("cisco-sa")
	ent := c.Query("enterpriseID")

	devices, err := postgresdb.DBInstance.AdminGetDevVAResultsBySA(vuln, strings.ToUpper(ent))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to find a match for vulnerability specified"})
		return
	}

	if len(devices) == 0 {
		c.JSON(http.StatusOK, gin.H{"results": "no device affected found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": devices})
}

func AdminGetCVEVulnAffectingDevice(c *gin.Context) {

	vuln := c.Param("cve-id")
	ent := c.Query("enterpriseID")

	devices, err := postgresdb.DBInstance.AdminGetDevVAResultsByCVE(strings.ToUpper(vuln), strings.ToUpper(ent))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to find a match for vulnerability specified"})
		return
	}

	if len(devices) == 0 {
		c.JSON(http.StatusOK, gin.H{"results": "no device affected found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": devices})
}

// AdminGetAnutaDeviceSuggestedSW will pull in bulk the devices and serial numbers from onboarded inventory devices
// API workflow to Cisco API's will then be triggered in order to retrieve the suggested SW versions for each device
func AdminGetAnutaDeviceSuggestedSW(c *gin.Context) {

	devList, err := postgresdb.DBInstance.FetchAllDevices()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot fetch devices list from DB"})
		return
	}

	// snSlice stores the Serial Number of Anuta devices
	var snSlice []string

	for _, dev := range devList {
		if dev.SerialNumber != "NA" {
			snSlice = append(snSlice, dev.SerialNumber)
		}
	}

	ciscoSNAPISlice := buildCiscoSNList(snSlice)

	// Store in Serial Number to Cisco Product ID Map
	var snToPIDMap []map[string]string

	for _, sn := range ciscoSNAPISlice {

		for _, pid := range sn.SerialNumbers {
			temp := map[string]string{
				"productID":    pid.OrderablePidList[0].OrderablePid,
				"serialNumber": pid.SrNo,
			}
			snToPIDMap = append(
				snToPIDMap,
				temp,
			)
		}

	}

	if len(snToPIDMap) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to process Serial Numbers from Cisco API"})
		return
	}

	// Extract Serial Numbers in slice to be passed to Cisco Software Suggestion API
	var sl []string

	for _, s := range snToPIDMap {
		if s["productID"] != "" {
			sl = append(sl, s["productID"])
		}
	}

	ciscoSuggSWAPISlice := buildCiscoSuggSWList(sl)

	if len(ciscoSuggSWAPISlice) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to fetch suggested SW from Cisco API"})
		return
	}

	tempSoftMap := map[string]string{}

	// Find out the most recently released suggested software per Cisco Product ID
	// Store in temporary Map for later comparison with snToPIDMap

	for _, allPID := range ciscoSuggSWAPISlice {
		for _, pid := range allPID.ProductList {

			var lastDate time.Time
			for _, sug := range pid.Suggestions {
				if sug.IsSuggested == "Y" {
					tempDate, errParseDate := time.Parse("02 Jan 2006", sug.ReleaseDate)

					if errParseDate != nil {
						logging.VulscanoLog("warning",
							"Unable to parse Date from Cisco Software Suggestion API: ", sug.ReleaseDate,
						)
						continue
					}

					if tempDate.After(lastDate) {
						lastDate = tempDate
						tempSoftMap[pid.Product.BasePID] = sug.ReleaseFormat2
					}
				}
			}
		}
	}

	// Merge snToPIDMap and DevList to have complete Mapping of Device, Serial Number, PID and Suggested Version
	for _, p := range snToPIDMap {
		if tempSoftMap[p["productID"]] == "" {
			p["suggestedVersion"] = "NA"
		} else {
			p["suggestedVersion"] = tempSoftMap[p["productID"]]
		}
		for _, d := range devList {
			if p["serialNumber"] == d.SerialNumber {
				p["deviceID"] = d.DeviceID
			}
		}
	}

	err = postgresdb.DBInstance.UpdateDeviceSuggestedSW(snToPIDMap)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot insert Suggested SW results in DB"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": snToPIDMap})

}

func LaunchBulkAdHocScan(c *gin.Context) {
	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}
	// ads represents struct for AdHocScanDevice body sent by API consumer
	var ads AdHocBulkScan

	// devScanner represents DeviceScanner interface. Depending on the OS Type given, we instantiate
	// with proper device vendor parameters
	var devScanner DeviceBulkScanner

	if err := c.ShouldBindJSON(&ads); err != nil {
		logging.VulscanoLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(ads.Devices) > 30 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum of 30 devices allowed for Bulk Scan"})
		return
	}

	switch ads.OSType {
	case ciscoIOSXE, ciscoIOS:
		devScanner = NewCiscoScanDevice(ads.OSType)
		if devScanner == nil {
			logging.VulscanoLog("error: ", "Failed to instantiate Device with given OS Type: ", ads.OSType)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to instantiate Device with given OS Type",
			})
			return
		}

	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Incorrect osType provided. Only IOS or IOS-XE supported",
		})
		return
	}

	scanRes, err := LaunchAbstractVendorBulkScan(devScanner, &ads, &jwtClaim)
	if err != nil {
		logging.VulscanoLog("error: ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"results": *scanRes,
	})
}

func LaunchAnutaInventoryBulkScan(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	var invDevices AnutaDeviceBulkScanRequest

	if err := c.ShouldBindJSON(&invDevices); err != nil {
		logging.VulscanoLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(invDevices.Devices) > 30 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum of 30 devices allowed for Bulk Scan"})
		return
	}

	entID, ok := jwtMapClaim["enterprise"].(string)

	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot determine user enterprise ID"})
		return
	}

	// Verify that users is allowed to run a Vulnerability Assessment on all devices specified from Anuta inventory
	notAllowedToScanSlice := make([]string, 0)

	for _, invDevice := range invDevices.Devices {

		if entID == invDevice.DeviceID[0:3] || isUserVulscanoRoot(jwtMapClaim) {
			continue
		}
		notAllowedToScanSlice = append(notAllowedToScanSlice, invDevice.DeviceID)
	}

	if len(notAllowedToScanSlice) > 0 {

		notAllowedToScanDevices := fmt.Sprint(notAllowedToScanSlice)
		c.JSON(http.StatusBadRequest,
			gin.H{"error": "you're not allowed to scan following device(s) " + notAllowedToScanDevices})
		return
	}

	bulkScanRet, err := AnutaInventoryBulkScan(&invDevices, &jwtClaim)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": *bulkScanRet})

}

// validateEmail is a helper function to validate email address format during user creation
func validateEmail(e string) bool {

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,
		61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

	return emailRegex.MatchString(e)
}

// validatePassword is a helper function to validate password meets minimum requirements
func validatePassword(p string) bool {
	validateCapital := regexp.MustCompile("[A-Z].*")
	validateCapitalBool := validateCapital.MatchString(p)

	validateLowerCase := regexp.MustCompile("[a-z].*")
	validateLowerCaseBool := validateLowerCase.MatchString(p)

	validateNumber := regexp.MustCompile("[0-9].*")
	validateNumberBool := validateNumber.MatchString(p)

	validateSpecialChar := regexp.MustCompile("[!@#$%^&*(){},<>?:;].*")
	validateSpecialCharBool := validateSpecialChar.MatchString(p)

	validatePasswordLengthBool := len(p) >= 10 && len(p) <= 20

	return validateCapitalBool && validateLowerCaseBool &&
		validateNumberBool && validateSpecialCharBool && validatePasswordLengthBool
}

// buildCiscoSNList is a helper function to fetch the Product ID's for each device passed in slice
func buildCiscoSNList(snSlice []string) []*openvulnapi.CiscoSnAPI {

	// Get the Cisco Product ID for each Serial Number
	// snIncrement will pass 10 serial numbers per API call until the snSlice exhausts
	// snTotalCountProc will keep track of the number of serial numbers processed in snSlice
	// snGuard will allow 5 concurrent API calls as per Cisco API limits
	snIncrement := 10

	if len(snSlice) < 21 {
		snIncrement = len(snSlice) / 2
	}

	snTotalCountProc := 0
	snMaxAPICalls := 5
	snGuard := make(chan struct{}, snMaxAPICalls)

	var wgSn sync.WaitGroup
	var muSn sync.RWMutex

	ciscoSNAPISlice := make([]*openvulnapi.CiscoSnAPI, 0)

	for snCount := 0; snCount+snIncrement < len(snSlice); snCount += snIncrement {
		snGuard <- struct{}{}
		wgSn.Add(1)
		go func(count int) {

			defer wgSn.Done()

			logging.VulscanoLog("info",
				"sending API Call for Serial Number ", snSlice[count:count+snIncrement])

			pid, err := openvulnapi.GetCiscoPID(snSlice[count : count+snIncrement]...)

			if err != nil {
				logging.VulscanoLog("error",
					err.Error())
				<-snGuard
				return
			}

			muSn.Lock()
			ciscoSNAPISlice = append(ciscoSNAPISlice, pid)
			snTotalCountProc = count
			muSn.Unlock()

			<-snGuard
		}(snCount)

	}
	wgSn.Wait()

	// Send last increment of serial numbers slice to Cisco API
	logging.VulscanoLog("info",
		"sending API Call for Serial Number ", snSlice[snTotalCountProc+snIncrement:])

	pidLast, err := openvulnapi.GetCiscoPID(snSlice[snTotalCountProc+snIncrement:]...)

	if err != nil {
		logging.VulscanoLog("error",
			err.Error())
	} else {
		ciscoSNAPISlice = append(ciscoSNAPISlice, pidLast)
	}
	return ciscoSNAPISlice
}

// buildCiscoSuggSWList is a helper function to fetch the Cisco suggested Software for each PID passed
func buildCiscoSuggSWList(snPID []string) []*openvulnapi.CiscoSWSuggestionAPI {

	// Get the Cisco SuggestedSW for each PID
	// snIncrement will pass 10 PID's per API call until the snSlice exhausts
	// snTotalCountProc will keep track of the number of PID's processed in snPID
	// snGuard will allow 2 concurrent API calls as per Cisco API limits
	pidIncrement := 10

	if len(snPID) < 21 {
		pidIncrement = len(snPID) / 2
	}

	pidTotalCountProc := 0
	pidMaxAPICalls := 2
	pidGuard := make(chan struct{}, pidMaxAPICalls)

	var wgSn sync.WaitGroup
	var muSn sync.RWMutex

	ciscoSuggSWSlice := make([]*openvulnapi.CiscoSWSuggestionAPI, 0)

	for snCount := 0; snCount+pidIncrement < len(snPID); snCount += pidIncrement {
		pidGuard <- struct{}{}
		wgSn.Add(1)
		go func(count int) {

			defer wgSn.Done()

			logging.VulscanoLog("info",
				"sending API Call for PID ", snPID[count:count+pidIncrement])

			sw, err := openvulnapi.GetCiscoSWSuggestion(snPID[count : count+pidIncrement]...)

			if err != nil {
				logging.VulscanoLog("error",
					err.Error())
				<-pidGuard
				return
			}

			muSn.Lock()
			ciscoSuggSWSlice = append(ciscoSuggSWSlice, sw)
			pidTotalCountProc = count
			muSn.Unlock()

			<-pidGuard
		}(snCount)

	}
	wgSn.Wait()

	// Send last increment of serial numbers slice to Cisco API
	logging.VulscanoLog("info",
		"sending API Call for Cisco PID ", snPID[pidTotalCountProc+pidIncrement:])

	swLast, err := openvulnapi.GetCiscoSWSuggestion(snPID[pidTotalCountProc+pidIncrement:]...)

	if err != nil {
		logging.VulscanoLog("error",
			err.Error())
	} else {
		ciscoSuggSWSlice = append(ciscoSuggSWSlice, swLast)
	}
	return ciscoSuggSWSlice
}
