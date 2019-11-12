// Vulscano Main application
// Main package will start the Gin REST API HTTP listener and graceful shutdown
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vscan/api/handlers"
	"github.com/lucabrasi83/vscan/api/routes"
	"github.com/lucabrasi83/vscan/datadiros"
	_ "github.com/lucabrasi83/vscan/docs" // docs is generated by Swag CLI, you have to import it.
	"github.com/lucabrasi83/vscan/logging"
	"github.com/lucabrasi83/vscan/postgresdb"
	"github.com/lucabrasi83/vscan/rediscache"
)

func main() {

	// Release Postgres Connection Pool
	defer postgresdb.ConnPool.Close()

	// Release Redis Connection Pool
	defer rediscache.CacheStore.CloseCacheConn()

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

	// Start scheduled batch jobs in PROD mode
	if os.Getenv("VSCAN_MODE") == "PROD" {
		schedTicker := time.NewTicker(24 * time.Hour)
		defer schedTicker.Stop()
		go handlers.SchedulerBatchJobs(schedTicker)
	} else {
		logging.VSCANLog("info", "VSCAN started in %s mode. Skipping scheduled batch jobs execution",
			os.Getenv("VSCAN_MODE"))
	}

	// Load HTTP Routes from api/routes package
	// Handlers are subsequently registered from api/handlers package
	routes.LoadRoutes(r)

	// At this stage, we know all init() functions did not return any error
	// and we were able to load Gin settings.
	logging.VSCANLog(
		"info",
		"All pre-checks passed. VSCAN Controller is now READY to accept requests on port %v", listenHTTPSPort)
	// Start Web API service in goroutine to handle graceful shutdown
	go func() {

		if err := srv.ListenAndServeTLS(
			filepath.FromSlash(datadiros.GetDataDir()+"/certs/vscan.pem"),
			filepath.FromSlash(datadiros.GetDataDir()+"/certs/vscan.key")); err != http.ErrServerClosed {

			logging.VSCANLog("fatal", "Error when starting Vulscano Server: %v", err)
		}

	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 1 minute.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	logging.VSCANLog("info",
		"Shutting Down VSCAN Controller Gracefully...",
	)
	// Purge cacheStoreClient when shutting down server
	err := rediscache.CacheStore.PurgeScannedDevices()

	if err != nil {
		logging.VSCANLog("error",
			"Failed to purge scanned devices cache store %v", err.Error(),
		)
	}

	// Serve ongoing Requests for 1 minute before shutting down
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logging.VSCANLog("fatal",
			"Failed to gracefully shutdown VSCAN Controller %v", err.Error(),
		)
	}
	logging.VSCANLog("info",
		"VSCAN Controller Gracefully Shutdown",
	)

	// TODO: Use Let's Encrypt issued certificate and auto-renewal
	//log.Fatal(autotls.Run(r, "vscan.asdlab.net"))

}
