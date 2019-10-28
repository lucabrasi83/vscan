package handlers

import (
	"net/http"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vscan/logging"
	"github.com/lucabrasi83/vscan/postgresdb"
)

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

func UpdateUserSSHGateway(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	userInput := c.Param("gw-name")

	var updateSSHGw UserSSHGatewayUpdate

	if err := c.ShouldBindJSON(&updateSSHGw); err != nil {
		logging.VSCANLog("error", "SSH Gateway update failed %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := postgresdb.DBInstance.UpdateUserSSHGateway(
		map[string]string{
			"gwName":       userInput,
			"gwIP":         updateSSHGw.GatewayIP,
			"gwUsername":   updateSSHGw.GatewayUsername,
			"gwPassword":   updateSSHGw.GatewayPassword,
			"gwPrivateKey": updateSSHGw.GatewayPrivateKey,
			"gwEnterprise": jwtClaim.Enterprise,
		},
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "SSH Gateway updated"})
}

func CreateUserSSHGateway(c *gin.Context) {

	jwtMapClaim := jwt.ExtractClaims(c)

	// Declare User attributes from JSON Web Token Claim
	jwtClaim := JwtClaim{
		Enterprise: jwtMapClaim["enterprise"].(string),
		UserID:     jwtMapClaim["userID"].(string),
		Email:      jwtMapClaim["email"].(string),
		Role:       jwtMapClaim["role"].(string),
	}

	var createSSHGw UserSSHGatewayCreate

	if err := c.ShouldBindJSON(&createSSHGw); err != nil {
		logging.VSCANLog("error", "SSH Gateway creation failed %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := postgresdb.DBInstance.CreateUserSSHGateway(
		map[string]string{
			"gwName":       createSSHGw.GatewayName,
			"gwIP":         createSSHGw.GatewayIP,
			"gwUsername":   createSSHGw.GatewayUsername,
			"gwPassword":   createSSHGw.GatewayPassword,
			"gwPrivateKey": createSSHGw.GatewayPrivateKey,
			"gwEnterprise": jwtClaim.Enterprise,
		},
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "SSH Gateway created"})
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

	sshgwObj := struct {
		SSHGateways []string `json:"sshGateways" binding:"required"`
	}{}

	if errBind := c.ShouldBindJSON(&sshgwObj); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sshGateways not specified in body"})
		return
	}

	userInput := sshgwObj.SSHGateways

	err := postgresdb.DBInstance.DeleteUserSSHGateway(jwtClaim.Enterprise, userInput)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete requested SSH gateways"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "deleted SSH gateways"})
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
