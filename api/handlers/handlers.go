package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vscan/initializer"
	"github.com/lucabrasi83/vscan/inventorymgr"
	"github.com/lucabrasi83/vscan/logging"
	"github.com/lucabrasi83/vscan/openvulnapi"
	"github.com/lucabrasi83/vscan/postgresdb"
	"github.com/lucabrasi83/vscan/rediscache"
)

const (
	rootRole        = "vulscanoroot"
	rootUser        = "root@vscan.com"
	userRole        = "vulscanouser"
	ciscoIOSXE      = "IOS-XE"
	ciscoIOS        = "IOS"
	bulkDevMaxLimit = 50
)

// LaunchAdHocScan handler is the API endpoint to trigger a single device ad-hoc VA scan.
// @Summary Launch On-Demand Vulnerability Scan
// @Tags admin
// @Description Perform a vulnerability scan any device NOT part of an inventory
// @Accept  json
// @Produce  json
// @Param Authorization header string true "JWT Bearer Token"
// @Param device-details body handlers.AdHocScanDevice true "Device Details"
// @Success 200 {object} handlers.ScanResults
// @Failure 400 {string} string "unable to launch scan"
// @Failure 404 {string} string "route requested does not exist"
// @Failure 401 {string} string "user not authorized"
// @Failure 413 {string} string "body size too large"
// @Router /admin/on-demand-scan [post]
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
		logging.VSCANLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	switch ads.OSType {
	case ciscoIOSXE, ciscoIOS:
		devScanner = NewCiscoScanDevice(ads.OSType)

	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Incorrect osType provided. Only IOS or IOS-XE supported",
		})
		return
	}

	scanRes, err := LaunchAbstractVendorScan(devScanner, &ads, &jwtClaim)
	if err != nil {
		logging.VSCANLog("error: ", err.Error())
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
		logging.VSCANLog("error", err.Error())
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
// @Summary Ping API Health Check
// @Tags ping
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

	cacheScannedDev, err := rediscache.CacheStore.LRangeScannedDevices()

	if err != nil {

		logging.VSCANLog("error", "unable to get the list of current scanned device: %v", err)

		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to get the list of current scanned device"})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"deviceCount": len(cacheScannedDev),
		"devicesIP":   cacheScannedDev,
	})

}

func GetUserDeviceCredentials(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	userInput := c.Param("creds-name")

	devCredsFound, err := postgresdb.DBInstance.FetchDeviceCredentials(jwtClaim.UserID, userInput)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot find requested device credentials"})
		return
	}

	c.JSON(http.StatusOK, *devCredsFound)
}
func DeleteUserDeviceCredentials(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	userInput := c.Param("creds-name")

	err := postgresdb.DBInstance.DeleteDeviceCredentials(jwtClaim.UserID, userInput)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete requested device credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "deleted " + userInput + " device credentials"})
}
func GetAllUserDeviceCredentials(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	devCredsFound, err := postgresdb.DBInstance.FetchAllUserDeviceCredentials(jwtClaim.UserID)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot find requested device credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deviceCredentials": devCredsFound})
}
func CreateUserDeviceCredentials(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	var newDevCreds DeviceCredentialsCreate

	if err := c.ShouldBindJSON(&newDevCreds); err != nil {
		logging.VSCANLog("error", "Device Credentials creation failed %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Temp to ensure only CISCO is used as vendor type while we add support for more vendors
	if newDevCreds.CredentialsDeviceVendor != "CISCO" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only CISCO supported as device vendor"})
		return
	}

	err := postgresdb.DBInstance.InsertNewDeviceCredentials(
		map[string]string{
			"credsName":       newDevCreds.CredentialsName,
			"credsVendor":     newDevCreds.CredentialsDeviceVendor,
			"credsUsername":   newDevCreds.Username,
			"credsPassword":   newDevCreds.Password,
			"credsPrivateKey": newDevCreds.PrivateKey,
			"credsIOSenable":  newDevCreds.IOSEnablePassword,
			"credsuserID":     jwtClaim.UserID,
		},
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "device credentials created"})
}
func UpdateUserDeviceCredentials(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	userInput := c.Param("creds-name")

	var updateDevCreds DeviceCredentialsUpdate

	if err := c.ShouldBindJSON(&updateDevCreds); err != nil {
		logging.VSCANLog("error", "Device Credentials update failed %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Temp to ensure only CISCO is used as vendor type while we add support for more vendors
	if updateDevCreds.CredentialsDeviceVendor != "" && updateDevCreds.CredentialsDeviceVendor != "CISCO" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only CISCO supported as device vendor"})
		return
	}

	err := postgresdb.DBInstance.UpdateDeviceCredentials(
		map[string]string{
			"credsCurrentName": userInput,
			"credsVendor":      updateDevCreds.CredentialsDeviceVendor,
			"credsUsername":    updateDevCreds.Username,
			"credsPassword":    updateDevCreds.Password,
			"credsPrivateKey":  updateDevCreds.PrivateKey,
			"credsIOSenable":   updateDevCreds.IOSEnablePassword,
			"credsuserID":      jwtClaim.UserID,
			"credsNewName":     updateDevCreds.CredentialsName,
		},
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "device credentials updated"})
}

func GetUserSSHGateway(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	userInput := c.Param("gw-name")

	sshgwFound, err := postgresdb.DBInstance.FetchUserSSHGateway(jwtClaim.Enterprise, userInput)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot find requested gateway"})
		return
	}

	c.JSON(http.StatusOK, *sshgwFound)
}
func GetAllUserSSHGateway(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	sshgwFound, err := postgresdb.DBInstance.FetchAllUserSSHGateway(jwtClaim.Enterprise)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot find requested gateway"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sshGateway": sshgwFound})
}
func DeleteUserSSHGateway(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	userInput := c.Param("gw-name")

	err := postgresdb.DBInstance.DeleteUserSSHGateway(jwtClaim.Enterprise, userInput)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot find requested gateway"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "gateway " + userInput + " deleted"})
}
func GetAllEnterprises(c *gin.Context) {
	ent, err := postgresdb.DBInstance.FetchAllEnterprises()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to fetch enterprises from database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"enterprises": ent})
}
func GetEnterprise(c *gin.Context) {

	userInput := strings.ToUpper(c.Param("enterprise-id"))

	ent, err := postgresdb.DBInstance.FetchEnterprise(userInput)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to fetch enterprises from database"})
		return
	}

	c.JSON(http.StatusOK, *ent)
}
func DeleteEnterprise(c *gin.Context) {

	userInput := strings.ToUpper(c.Param("enterprise-id"))

	err := postgresdb.DBInstance.DeleteEnterprise(userInput)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to delete enterprise: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "enterprise " + userInput + " successfully deleted"})
}
func CreateEnterprise(c *gin.Context) {

	var newEnt EnterpriseCreate

	if err := c.ShouldBindJSON(&newEnt); err != nil {
		logging.VSCANLog("error", "Enterprise creation failed %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := postgresdb.DBInstance.InsertNewEnterprise(
		map[string]string{
			"entID":   strings.ToUpper(newEnt.EnterpriseID),
			"entName": newEnt.EnterpriseName,
		},
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "enterprise successfully created"})
}

// GetAllUsers is a Gin Handler to return the list of all users provisioned
func GetAllUsers(c *gin.Context) {
	users, err := postgresdb.DBInstance.FetchAllUsers()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to fetch users from database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// GetUser is a Gin handler to return a specific user
func GetUser(c *gin.Context) {
	userInput := c.Param("user-id")

	userFound, err := postgresdb.DBInstance.FetchUser(userInput)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot find requested user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": *userFound})
}

// CreateUser is a Gin handler to create a user
func CreateUser(c *gin.Context) {

	var newUser VulscanoUserCreate

	if err := c.ShouldBindJSON(&newUser); err != nil {
		logging.VSCANLog("error", "User creation request failed %v", err)
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

// UpdateUser is a Gin handler to update a user
func UpdateUser(c *gin.Context) {

	var updateUser VulscanoUserPatch
	user := c.Param("user-id")

	if err := c.ShouldBindJSON(&updateUser); err != nil {
		logging.VSCANLog("error", "user update request failed %v", err)
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

// DeleteUser is a Gin handler to delete a user
// @Summary Delete an existing user
// @Tags admin
// @Description Delete an existing user
// @Accept  json
// @Produce  json
// @Param Authorization header string true "JWT Bearer Token"
// @Param username path string true "Username in email format"
// @Success 200 {string} string "user successfully deleted"
// @Failure 400 {string} string "unable to update requested user"
// @Failure 404 {string} string "route requested does not exist"
// @Failure 401 {string} string "user not authorized"
// @Failure 413 {string} string "body size too large"
// @Router /admin/user/{username} [delete]
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

// GetAnutaDeviceSuggestedSW will pull in bulk the devices and serial numbers from onboarded inventory devices
// API workflow to Cisco API's will then be triggered in order to retrieve the suggested SW versions for each device
func GetAnutaDeviceSuggestedSW() ([]map[string]string, error) {

	devList, err := postgresdb.DBInstance.AdminGetAllDevices("")

	if err != nil {
		return nil, err
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
		return nil, errors.New("unable to fetch suggested SW from Cisco API")
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

		return nil, errors.New("unable to fetch suggested SW from Cisco API")
	}

	tempSoftMap := map[string]string{}

	// Find out the most recently released suggested software per Cisco Product ID
	// Store in temporary Map for later comparison with snToPIDMap

	for _, allPID := range ciscoSuggSWAPISlice {
		for _, pid := range allPID.ProductList {
			// Only parse IOS / IOSXE software as temporary workaround
			// Cisco Suggested SW API returns multiple results for each product variant
			if pid.Product.SoftwareType == "IOS XE Software" || pid.Product.SoftwareType == "IOS Software" {
				var lastDate time.Time
				for _, sug := range pid.Suggestions {
					if sug.IsSuggested == "Y" {
						tempDate, errParseDate := time.Parse("02 Jan 2006", sug.ReleaseDate)

						if errParseDate != nil {
							logging.VSCANLog("warning",
								"Unable to parse Date from Cisco Software Suggestion API: %v ", errParseDate,
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
		return nil, err
	}
	logging.VSCANLog("info",
		"Synchronization task of Devices Suggested Software with Cisco API has completed")

	return snToPIDMap, nil
}

// AdminGetAnutaDeviceSuggestedSW will pull in bulk the devices and serial numbers from onboarded inventory devices
// API workflow to Cisco API's will then be triggered in order to retrieve the suggested SW versions for each device
func AdminGetAnutaDeviceSuggestedSW(c *gin.Context) {

	snToPIDMap, err := GetAnutaDeviceSuggestedSW()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot fetch devices list from DB"})
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
		logging.VSCANLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(ads.Devices) > bulkDevMaxLimit {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum of " + strconv.Itoa(
			bulkDevMaxLimit) + " devices allowed for Bulk Scan"})
		return
	}

	switch ads.OSType {
	case ciscoIOSXE, ciscoIOS:
		devScanner = NewCiscoScanDevice(ads.OSType)

	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Incorrect osType provided. Only IOS or IOS-XE supported",
		})
		return
	}

	scanRes, err := LaunchAbstractVendorBulkScan(devScanner, &ads, &jwtClaim)
	if err != nil {
		logging.VSCANLog("error: ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"results": *scanRes,
	})
}

func AdminGetAllInventoryDevices(c *gin.Context) {

	ent := c.Query("enterpriseID")

	devices, err := postgresdb.DBInstance.AdminGetAllDevices(ent)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to retrieve devices from inventory"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"devices": devices})
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
		logging.VSCANLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(invDevices.Devices) > bulkDevMaxLimit {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum of " + strconv.Itoa(
			bulkDevMaxLimit) + " devices allowed for Bulk Scan"})
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

	emailRegex := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

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
func buildCiscoSNList(snSlice []string) []openvulnapi.CiscoSnAPI {

	logging.VSCANLog("info",
		"Start Fetching Product ID of inventory devices from Cisco SN2INFO API...")

	// If Serial Number slice less than 5, exit the function
	if len(snSlice) < 5 {
		logging.VSCANLog("info",
			"Less than 5 Serial Numbers to query on Cisco SN2INFO API: %v. Cancelling the request",
			snSlice)

		return nil
	}

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

	ciscoSNAPISlice := make([]openvulnapi.CiscoSnAPI, 0)

	for snCount := 0; snCount+snIncrement < len(snSlice); snCount += snIncrement {
		snGuard <- struct{}{}
		wgSn.Add(1)
		go func(count int) {

			defer wgSn.Done()

			pid, err := openvulnapi.GetCiscoPID(snSlice[count : count+snIncrement]...)

			if err != nil {
				logging.VSCANLog("error",
					err.Error())
				<-snGuard
				return
			}

			muSn.Lock()
			ciscoSNAPISlice = append(ciscoSNAPISlice, *pid)
			snTotalCountProc = count
			muSn.Unlock()

			<-snGuard
		}(snCount)

	}
	wgSn.Wait()

	pidLast, err := openvulnapi.GetCiscoPID(snSlice[snTotalCountProc+snIncrement:]...)

	if err != nil {
		logging.VSCANLog("error",
			err.Error())
	} else {
		ciscoSNAPISlice = append(ciscoSNAPISlice, *pidLast)
	}
	logging.VSCANLog("info",
		"Done Fetching Product ID of inventory devices from Cisco SN2INFO API.")

	return ciscoSNAPISlice
}

// buildCiscoSuggSWList is a helper function to fetch the Cisco suggested Software for each PID passed
func buildCiscoSuggSWList(snPID []string) []openvulnapi.CiscoSWSuggestionAPI {

	logging.VSCANLog("info",
		"Start Fetching Suggested Software releases of inventory devices from Cisco Suggested SW API...")

	// If no Product ID is present in the slice, exit the function
	if len(snPID) < 5 {

		logging.VSCANLog("info",
			"Less than 5 Product ID's to query: %v on Cisco Suggested SW API. Cancelling the request",
			snPID)

		return nil
	}
	// Get the Cisco SuggestedSW for each PID
	// snIncrement will pass 10 PID's per API call until the snPID exhausts
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

	ciscoSuggSWSlice := make([]openvulnapi.CiscoSWSuggestionAPI, 0)

	for snCount := 0; snCount+pidIncrement < len(snPID); snCount += pidIncrement {
		pidGuard <- struct{}{}
		wgSn.Add(1)
		go func(count int) {

			defer wgSn.Done()

			sw, err := openvulnapi.GetCiscoSWSuggestion(snPID[count : count+pidIncrement]...)

			if err != nil {
				logging.VSCANLog("error",
					err.Error())
				<-pidGuard
				return
			}

			muSn.Lock()
			ciscoSuggSWSlice = append(ciscoSuggSWSlice, *sw)
			pidTotalCountProc = count
			muSn.Unlock()

			<-pidGuard
		}(snCount)

	}
	wgSn.Wait()

	swLast, err := openvulnapi.GetCiscoSWSuggestion(snPID[pidTotalCountProc+pidIncrement:]...)

	if err != nil {
		logging.VSCANLog("error",
			err.Error())
	} else {
		ciscoSuggSWSlice = append(ciscoSuggSWSlice, *swLast)
	}
	logging.VSCANLog("info",
		"Done Fetching Suggested Software version of inventory devices from Cisco Suggested SW API.")

	return ciscoSuggSWSlice
}

// RefreshInventoryCache is going to update the Redis cache with inventory information pulled from the different
// integrations
func RefreshInventoryCache(c *gin.Context) {
	inventorymgr.BuildDevicesInventory()

	c.JSON(http.StatusOK, gin.H{"reply": "request to rebuild inventory cache submitted."})
}

// FetchCiscoAMCStatus is the function that will interact with Cisco SN2INFO API and update Cisco CPE inventories
// with their Maintenance Contract Status
func FetchCiscoAMCStatus() error {

	logging.VSCANLog("info",
		"Start fetching Cisco SmartNet coverage status from Cisco API...")

	// Maximum Serial Number per API call
	const maxSN = 50

	devList, err := postgresdb.DBInstance.AdminGetAllDevices("")

	if err != nil {
		return err
	}

	// sn stores the Serial Number of devices within the inventory
	var sn []string

	for _, dev := range devList {
		if dev.SerialNumber != "NA" {
			sn = append(sn, dev.SerialNumber)

		}
	}

	if len(sn) <= maxSN {

		snAMCMap, err := getCiscoAMC(sn...)

		if err != nil {

			return err
		}

		err = postgresdb.DBInstance.UpdateSmartNetCoverage(snAMCMap)

		if err != nil {

			return err
		}

	} else if len(sn) > maxSN {

		// Keeps track of how many Serial Numbers left for request
		currentCountSn := len(sn)

		// Channel Guard for maximum 5 concurrent API calls
		const maxConcurAPICalls = 5
		guard := make(chan struct{}, maxConcurAPICalls)

		// Wait Group for concurrent requests to Cisco SN2INFO API
		var wg sync.WaitGroup

		// Mutex to avoid race condition
		var mu sync.Mutex

		// Merged slice of all Serial Numbers / Coverage status retrieved from Cisco
		var snAMCMapParent []map[string]string

		for i := 0; currentCountSn >= maxSN; i++ {

			guard <- struct{}{}
			wg.Add(1)

			// We don't decrement the current count on the first loop iteration
			if i != 0 {

				currentCountSn -= maxSN

			}

			go func(count int) {

				defer wg.Done()

				// Once count - maxSN returns a negative number, we know we're at the end of the sn Slice
				// Therefore we just take the current index until what's left
				if len(sn)-(count-maxSN) > len(sn) {

					snAMCMapChild, err := getCiscoAMC(sn[len(sn)-count:]...)

					if err != nil {
						<-guard
						return
					}

					mu.Lock()
					snAMCMapParent = append(snAMCMapParent, snAMCMapChild...)
					mu.Unlock()

				} else {

					// For each iteration, we take the starting index length of slice - current count
					// Ending index length of slice - (current count - maximum serial numbers in single API call)
					snAMCMapChild, err := getCiscoAMC(sn[len(sn)-count : len(sn)-(count-maxSN)]...)

					if err != nil {
						<-guard
						return
					}

					mu.Lock()
					snAMCMapParent = append(snAMCMapParent, snAMCMapChild...)
					mu.Unlock()

				}
				// Decrement the number of serial numbers left to request

				<-guard
			}(currentCountSn)
		}

		wg.Wait()

		if len(snAMCMapParent) == 0 {

			return errors.New("failed to retrieve SmartNet Coverage from Cisco SN2INFO")
		}

		err = postgresdb.DBInstance.UpdateSmartNetCoverage(snAMCMapParent)

		if err != nil {
			return errors.New("cannot insert Cisco SmartNet Coverage in DB")
		}

	}
	logging.VSCANLog("info",
		"Synchronization task of SmartNet coverage status from Cisco API has completed.")

	return nil
}

// FetchCiscoAMCStatus is the function that will interact with Cisco SN2INFO API and update Cisco CPE inventories
// with their Maintenance Contract Status
func AdminFetchCiscoAMCStatus(c *gin.Context) {

	err := FetchCiscoAMCStatus()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to reconcile Device AMC status with Cisco API"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "Cisco AMC contract details successfully retrieved."})

}

func getCiscoAMC(sn ...string) ([]map[string]string, error) {

	resp, err := openvulnapi.GetSmartNetCoverage(sn...)

	if err != nil {
		return nil, err
	}

	var snAMCMap []map[string]string
	for _, res := range resp.SerialNumbers {
		snAMCMap = append(snAMCMap, map[string]string{
			"serialNumber":               res.SrNo,
			"productID":                  res.OrderablePidList[0].OrderablePid,
			"serviceContractAssociated":  res.IsCovered,
			"serviceContractDescription": res.ServiceLineDescr,
			"serviceContractNumber":      res.ServiceContractNumber,
			"serviceContractEndDate":     res.CoveredProductLineEndDate,
			"serviceContractSiteCountry": res.ContractSiteCountry,
		})
	}

	return snAMCMap, nil
}
