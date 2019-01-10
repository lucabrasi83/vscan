package main

import (
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/api/routes"
	"github.com/lucabrasi83/vulscano/datadiros"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/postgresdb"
)

func main() {

	// Release Postgres Connection Pool
	defer postgresdb.ConnPool.Close()

	// Set Gin Logging to file and StdOut.
	ginLogFile, err := os.OpenFile(
		filepath.FromSlash(datadiros.GetDataDir()+"/logs/gingonic.log"),
		os.O_WRONLY|os.O_CREATE|os.O_APPEND,
		0644)
	if err != nil {
		logging.VulscanoLog("error",
			"Failed to open gingonic.log file: ", err.Error())
	}

	defer ginLogFile.Close()

	gin.DefaultWriter = io.MultiWriter(os.Stdout, ginLogFile)

	// Flag to set gin in production mode
	gin.SetMode(gin.ReleaseMode)

	// Set Default Gin-Gonic HTTP router mux
	r := gin.Default()

	// Load HTTP Routes from api/routes package
	// Handlers are subsequently registered from api/handlers package
	routes.LoadRoutes(r)

	// At this stage, we know all init() functions did not return any error
	// and we were able to load Gin settings.
	logging.VulscanoLog(
		"info",
		"All pre-checks passed. Vulscano is now READY to start!")

	// Start Web API service
	if err := r.RunTLS(
		":8443",
		filepath.FromSlash(datadiros.GetDataDir()+"/certs/vulscano.pem"),
		filepath.FromSlash(datadiros.GetDataDir()+"/certs/vulscano.key")); err != nil {

		log.Fatalln("Error when starting application:", err)
	}
	// TODO: Use Let's Encrypt issued certificate and auto-renewal
	//log.Fatal(autotls.Run(r, "vulscano.asdlab.net"))

}
