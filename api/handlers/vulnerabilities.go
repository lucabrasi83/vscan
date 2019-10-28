package handlers

import (
	"net/http"
	"strconv"
	"strings"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vscan/postgresdb"
)

func GetAllVulnAffectingDevice(c *gin.Context) {

	// Extract JWT Claim
	jwtMapClaim := jwt.ExtractClaims(c)

	var ent string

	devID := c.Param("device-name")

	if devID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device ID param missing in request"})
		return
	}

	if isUserVulscanoRoot(jwtMapClaim) {
		ent = c.Query("enterpriseID")
	} else {
		ent = jwtMapClaim["enterprise"].(string)
	}

	vuln, err := postgresdb.DBInstance.DBVulnAffectingDevice(devID, ent)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to find a match for device specified"})
		return
	}

	if len(vuln) == 0 {
		c.JSON(http.StatusOK, gin.H{"results": "no vulnerability found for this device"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": vuln})

}

func GetVulnDeviceHistory(c *gin.Context) {

	// Extract JWT Claim
	jwtMapClaim := jwt.ExtractClaims(c)

	var ent string

	devID := c.Param("device-name")

	limit, errConv := strconv.Atoi(c.Query("recordLimit"))

	if errConv != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enter a valid numeric value for record limit"})
		return
	}

	if limit == 0 {
		limit = 5
	}

	if devID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device ID param missing in request"})
		return
	}

	if isUserVulscanoRoot(jwtMapClaim) {
		ent = c.Query("enterpriseID")
	} else {
		ent = jwtMapClaim["enterprise"].(string)
	}

	if ent == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enterpriseID query param missing in request"})
		return
	}

	vuln, err := postgresdb.DBInstance.DBVulnDeviceHistory(devID, ent, limit)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to find a match for device specified"})
		return
	}

	if len(vuln) == 0 {
		c.JSON(http.StatusOK, gin.H{"results": "no vulnerability history found for this device"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": vuln})

}

func GetSAVulnAffectingDevice(c *gin.Context) {

	// Extract JWT Claim
	jwtMapClaim := jwt.ExtractClaims(c)

	var ent string

	if isUserVulscanoRoot(jwtMapClaim) {
		ent = c.Query("enterpriseID")
	} else {
		ent = jwtMapClaim["enterprise"].(string)
	}

	vuln := c.Param("cisco-sa")

	devices, err := postgresdb.DBInstance.GetDevVAResultsBySA(vuln, strings.ToUpper(ent))

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

func GetCVEVulnAffectingDevice(c *gin.Context) {

	// Extract JWT Claim
	jwtMapClaim := jwt.ExtractClaims(c)

	var ent string

	if isUserVulscanoRoot(jwtMapClaim) {
		ent = c.Query("enterpriseID")
	} else {
		ent = jwtMapClaim["enterprise"].(string)
	}

	vuln := c.Param("cve-id")

	devices, err := postgresdb.DBInstance.GetDevVAResultsByCVE(strings.ToUpper(vuln), strings.ToUpper(ent))

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
