package handlers

import (
	"github.com/lucabrasi83/vulscano/initializer"
	"net/http"
	"regexp"
	"runtime"
	"strings"

	"github.com/appleboy/gin-jwt"

	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/postgresdb"
)

const (
	rootRole = "vulscanoroot"
	rootUser = "root@vulscano.com"
	userRole = "vulscanouser"
)

// LaunchAdHocScan handler is the API endpoint to trigger a single device ad-hoc VA scan on the passed JSON body.
// The JSON body should be formatted as per below example:
//	{
//	"hostname": "CSR1000V_RTR1",
//	"ip": "192.168.1.70",
//	"os_type": "IOS-XE",
//	"os_version": "16.06.03
//	}
//
//
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
	case "IOS-XE", "IOS":
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
			"error": "Incorrect OS_Type provided. Only IOS or IOS-XE supported",
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
// The JSON body should be formatted as per below example:
//	{
//	"deviceId": "CSR1000V_RTR1",
//	}
//
//
func LaunchAnutaInventoryScan(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	var invDevice AnutaDeviceScanRequest

	if err := c.ShouldBindJSON(&invDevice); err != nil {
		logging.VulscanoLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Control to verify user Enterprise ID corresponds to Device trigram
	if entID, ok := jwtMapClaim["enterprise"].(string); ok && (entID == string(invDevice.
		DeviceID[:3]) || isUserVulscanoRoot(jwtMapClaim)) {

		jwtClaim := JwtClaim{
			Enterprise: jwtMapClaim["enterprise"].(string),
			UserID:     jwtMapClaim["userID"].(string),
			Email:      jwtMapClaim["email"].(string),
			Role:       jwtMapClaim["role"].(string),
		}

		dev, res, errAnutaAPI := AnutaInventoryScan(&invDevice, &jwtClaim)

		if errAnutaAPI != nil {

			c.JSON(http.StatusBadRequest, gin.H{
				"error": errAnutaAPI.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"deviceDetails": *dev, "results": *res})
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
func Ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"pong":          "I'm alive!",
		"version":       initializer.Version,
		"golangRuntime": runtime.Version(),
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

	if isDBUser := postgresdb.DBInstance.AssertUserExists(user); isDBUser == false {
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

	if isDBUser := postgresdb.DBInstance.AssertUserExists(user); isDBUser == false {
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

	if len(*devices) == 0 {
		c.JSON(http.StatusOK, gin.H{"results": "no device affected found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": *devices})
}

func AdminGetCVEVulnAffectingDevice(c *gin.Context) {

	vuln := c.Param("cve-id")
	ent := c.Query("enterpriseID")

	devices, err := postgresdb.DBInstance.AdminGetDevVAResultsByCVE(strings.ToUpper(vuln), strings.ToUpper(ent))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to find a match for vulnerability specified"})
		return
	}

	if len(*devices) == 0 {
		c.JSON(http.StatusOK, gin.H{"results": "no device affected found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": *devices})
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

	return validateCapitalBool && validateLowerCaseBool && validateNumberBool && validateSpecialCharBool && validatePasswordLengthBool
}
