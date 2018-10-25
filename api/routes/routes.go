package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/api/handlers"
)

func LoadRoutes(routes *gin.Engine) {
	// Set up default handler for no routes found
	routes.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{"error": "404 - PAGE_NOT_FOUND", "message": "Requested route does not exist"})
	})
	// /api/v1 Routes group and associated handlers
	apiV1 := routes.Group("/api/v1")
	{
		apiV1.POST("/ciscosameta", handlers.GetCiscoVulnBySA)
		apiV1.POST("/ondemandscan", handlers.LaunchAdHocScan)
	}
}
