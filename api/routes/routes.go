// Package routes handles registration of API endpoints for Gin framework.
package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/api/handlers"
	"github.com/lucabrasi83/vulscano/api/middleware"
	"net/http"
)

func LoadRoutes(routes *gin.Engine) {
	// Set up default handler for no routes found
	routes.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{"error": "404 - PAGE_NOT_FOUND", "message": "Requested route does not exist"})
	})

	// /api/v1 Routes group and associated handlers

	// Register JSON Web Token Middleware
	jwtMiddleware := middleware.JwtConfigGenerate()

	// Short hand declaration for JWT Middleware
	authWare := jwtMiddleware.MiddlewareFunc

	apiV1 := routes.Group("/api/v1")
	{
		// Set Limit 2KB maximum for Request Size
		apiV1.Use(middleware.RequestSizeLimiter(2048))

		apiV1.POST("/login", jwtMiddleware.LoginHandler)
		apiV1.GET("/ping", handlers.Ping)

		admin := apiV1.Group("/admin").Use(authWare())
		{
			admin.POST("/on-demand-scan", handlers.LaunchAdHocScan)
			admin.POST("/bulk-on-demand-scan", handlers.LaunchAdHocScan)
			admin.POST("/update-all-cisco-sa", handlers.UpdateCiscoOpenVulnSAAll)
			admin.GET("/user/:user-id", handlers.GetUser)
			admin.GET("/all-users", handlers.GetAllUsers)
			admin.POST("/user", handlers.CreateUser)
			admin.PATCH("/user/:user-id", handlers.UpdateUser)
			admin.DELETE("/user/:user-id", handlers.DeleteUser)
			admin.GET("/enterprise/:enterprise-id", tempHandler)
			admin.GET("/all-enterprises", tempHandler)
			admin.POST("/enterprise", tempHandler)
			admin.PATCH("/enterprise/:enterprise-id", tempHandler)
			admin.DELETE("/enterprise/:enterprise-id", tempHandler)
		}

		vulnAdmin := apiV1.Group("/admin/vulnerabilities").Use(authWare())
		{
			vulnAdmin.GET("/cisco-advisory/:cisco-sa", handlers.AdminGetSAVulnAffectingDevice)
			vulnAdmin.GET("/cve/:cve-id", handlers.AdminGetCVEVulnAffectingDevice)
			vulnAdmin.GET("/device/:device-name", tempHandler)
		}

		scan := apiV1.Group("/scan").Use(authWare())
		{
			scan.POST("/anuta-inventory-device", authWare(), handlers.LaunchAnutaInventoryScan)
			scan.POST("/bulk-anuta-inventory", authWare(), handlers.LaunchAnutaInventoryScan)
		}
		vuln := apiV1.Group("/vulnerabilities").Use(authWare())
		{
			vuln.GET("/cisco-advisory/:cisco-sa", tempHandler)
			vuln.GET("/cve/:cve-id", tempHandler)
			vuln.GET("/device/:device-name", tempHandler)
			vuln.GET("/cisco-published-sa", tempHandler)
			vuln.GET("/summary", tempHandler)
		}

	}

}

func tempHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"test": "ok"})
}
