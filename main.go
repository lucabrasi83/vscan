package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

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

	// Store Gin Default Logs in gingonic.log file
	gin.DefaultWriter = ginLogFile

	// Flag to set gin in production mode
	gin.SetMode(gin.ReleaseMode)

	// Set Default Gin-Gonic HTTP router mux
	r := gin.Default()

	// Get HTTPS Listening Port from Environment Variable
	listenHTTPSPort := os.Getenv("VULSCANO_HTTPS_PORT")

	if listenHTTPSPort == "" {
		listenHTTPSPort = "8443"
	}

	srv := &http.Server{
		Addr:    ":" + listenHTTPSPort,
		Handler: r,
	}

	// Load HTTP Routes from api/routes package
	// Handlers are subsequently registered from api/handlers package
	routes.LoadRoutes(r)

	// At this stage, we know all init() functions did not return any error
	// and we were able to load Gin settings.
	logging.VulscanoLog(
		"info",
		"All pre-checks passed. Vulscano is now READY to accept requests!")

	// Start Web API service in goroutine to handle graceful shutdown
	go func() {

		if err := srv.ListenAndServeTLS(
			filepath.FromSlash(datadiros.GetDataDir()+"/certs/vulscano.pem"),
			filepath.FromSlash(datadiros.GetDataDir()+"/certs/vulscano.key")); err != http.ErrServerClosed {

			logging.VulscanoLog("fatal", "Error when starting Vulscano Server: ", err.Error())
		}

	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 1 minute.
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit
	logging.VulscanoLog("info",
		"Shutting Down Vulscano Server Gracefully...",
	)

	// Serve ongoing Requests for 1 minute before shutting down
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logging.VulscanoLog("fatal",
			"Failed to gracefully shutdown Vulscano server ", err.Error(),
		)
	}
	logging.VulscanoLog("info",
		"Vulscano Server Gracefully Shutdown",
	)

	// TODO: Use Let's Encrypt issued certificate and auto-renewal
	//log.Fatal(autotls.Run(r, "vulscano.asdlab.net"))

}
