package handlers

import (
	"net/http"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vscan/logging"
	"github.com/lucabrasi83/vscan/postgresdb"
)

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

func DeleteUserDeviceCredentials(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	credsObj := struct {
		Credentials []string `json:"credentials" binding:"required"`
	}{}

	if errBind := c.ShouldBindJSON(&credsObj); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "credentials not specified in body"})
		return
	}

	userInput := credsObj.Credentials

	err := postgresdb.DBInstance.DeleteDeviceCredentials(jwtClaim.UserID, userInput)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete requested device credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "deleted device credentials"})
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
