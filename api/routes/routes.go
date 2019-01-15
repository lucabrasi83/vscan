// Package routes handles registration of API endpoints for Gin framework.
package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/api/handlers"
	"github.com/lucabrasi83/vulscano/api/middleware"
)

func LoadRoutes(routes *gin.Engine) {
	// Set up default handler for no routes found
	routes.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{"error": "404 - PAGE_NOT_FOUND", "message": "Requested route does not exist"})
	})
	// /api/v1 Routes group and associated handlers

	jwtMiddleware := middleware.JwtConfigGenerate()

	// Short hand declaration for JWT Middleware
	authWare := jwtMiddleware.MiddlewareFunc

	apiV1 := routes.Group("/api/v1")
	{
		apiV1.POST("/cisco-sa-meta", authWare(), handlers.GetCiscoVulnBySA)
		apiV1.POST("/on-demand-scan", authWare(), handlers.LaunchAdHocScan)
		apiV1.POST("/update-all-cisco-sa", authWare(), handlers.UpdateCiscoOpenVulnSAAll)
		apiV1.POST("/anuta-inventory-device-scan", authWare(), handlers.LaunchAnutaInventoryScan)
		apiV1.POST("/login", jwtMiddleware.LoginHandler)
		apiV1.GET("/ping", handlers.Ping)
	}

}
