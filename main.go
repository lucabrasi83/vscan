package main

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/autotls"
	"github.com/lucabrasi83/vulscano/api/routes"
	"log"
)


func main() {

	//gin.SetMode(gin.ReleaseMode)

	// Set Default Gin-Gonic HTTP router mux
	r := gin.Default()

	// Load HTTP Routes from api/routes package
	// Handlers are subsequently registered from api/handlers package
	routes.LoadRoutes(r)

	//if err:= r.RunTLS(":8443", "./certs/vulscanocert.pem", "./certs/PrivateKey.key"); err != nil{
	//	log.Fatalln("Error when starting application:", err)
	//}
	log.Fatal(autotls.Run(r, "vulscano.asdlab.net"))
}