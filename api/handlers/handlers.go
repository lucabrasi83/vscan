package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/openvulnapi"
	"net/http"
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
	var ads AdHocScanDevice
	if err := c.ShouldBindJSON(&ads); err != nil {
		logging.VulscanoLog("error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	switch ads.OSType {
	case "IOS-XE":
		d := newCiscoIOSXEDevice()
		scanRes, err := d.Scan(&ads)
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
	}
}
