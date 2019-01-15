package handlers

import (
	"github.com/lucabrasi83/vulscano/initializer"
	"net/http"
	"runtime"

	"github.com/appleboy/gin-jwt"

	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/openvulnapi"
	"github.com/lucabrasi83/vulscano/postgresdb"
)

func GetCiscoVulnBySA(c *gin.Context) {

	var sa CiscoSecurityAdvisory
	if err := c.ShouldBindJSON(&sa); err != nil {
		logging.VulscanoLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s, err := openvulnapi.GetVulnMetaData(sa.CiscoAdvisoryID)
	if err != nil {
		logging.VulscanoLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"vulnmeta": (*s)[0],
	})
}

// LaunchAdHocScan handler is the API endpoint to trigger an ad-hoc VA scan on the passed JSON body.
// The JSON body should be formatted as per below example:
//	{
//	"hostname": "CSR1000V_RTR1",
//	"ip": "192.168.1.70",
//	"os_type": "IOS-XE"
//	}
//
//
func LaunchAdHocScan(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	var ads AdHocScanDevice

	if err := c.ShouldBindJSON(&ads); err != nil {
		logging.VulscanoLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	switch ads.OSType {
	case "IOS-XE":
		d := newCiscoIOSXEDevice()
		scanRes, err := d.Scan(&ads, &jwtClaim)
		if err != nil {
			logging.VulscanoLog("error", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"results": *scanRes,
		})
	case "IOS":
		d := newCiscoIOSDevice()
		scanRes, err := d.Scan(&ads, &jwtClaim)
		if err != nil {
			logging.VulscanoLog("error", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"results": *scanRes,
		})
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Incorrect OS_Type provided. Only IOS or IOS-XE supported",
		})
	}
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
	if role, ok := jwtMapClaim["role"].(string); ok && role == "vulscanoroot" {
		return true
	}
	return false
}

// PingVulscano is a health check status handler of the Vulscano API
func Ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"pong":          "I'm alive!",
		"version":       initializer.Version,
		"golangRuntime": runtime.Version(),
	})
}
