package main

import (
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/api/routes"
	"github.com/lucabrasi83/vulscano/datadiros"
	"log"
	"path/filepath"
)

func main() {

	// Flag to set gin in production mode
	gin.SetMode(gin.ReleaseMode)

	// Set Default Gin-Gonic HTTP router mux
	r := gin.Default()

	// Load HTTP Routes from api/routes package
	// Handlers are subsequently registered from api/handlers package
	routes.LoadRoutes(r)

	if err := r.RunTLS(
		":8443",
		filepath.FromSlash(datadiros.GetDataDir()+"/certs/vulscano.pem"),
		filepath.FromSlash(datadiros.GetDataDir()+"/certs/vulscano.key")); err != nil {

		log.Fatalln("Error when starting application:", err)
	}
	// TODO: Use Let's Encrypt issued certificate and auto-renewal
	//log.Fatal(autotls.Run(r, "vulscano.asdlab.net"))

}
