package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/hashgen"
	"github.com/lucabrasi83/vulscano/inibuilder"
	"github.com/lucabrasi83/vulscano/openvulnapi"
	"log"
	"net/http"
)

func Ping(c *gin.Context) {

	devices := map[string]string{
		"CPE1": "10.1.1.1",
		"CPE2": "10.2.2.2",
	}

	// We Generate a Scan Job ID from HashGen library
	JobID, errHash := hashgen.GenHash()
	if errHash != nil {
		log.Println("Error when generating hash: ", errHash)
	}
	if errIniBuilder := inibuilder.BuildIni(JobID, devices); errIniBuilder != nil {
		log.Println(errIniBuilder)
	}
	c.JSON(http.StatusOK, gin.H{
		"message": JobID,
	})
}

func CiscoPing(c *gin.Context) {
	s, err := openvulnapi.GetOpenVulnToken()
	if err != nil {
		log.Println(err)
	}
	c.JSON(http.StatusOK, gin.H{
		"token": s,
	})
}
