package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vscan/logging"
	"github.com/lucabrasi83/vscan/postgresdb"
)

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
