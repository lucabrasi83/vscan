// Package routes handles registration of API endpoints for Gin framework.
package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vscan/api/handlers"
	"github.com/lucabrasi83/vscan/api/middleware"
	"github.com/swaggo/gin-swagger"
	"github.com/swaggo/gin-swagger/swaggerFiles"
	ginprometheus "github.com/zsais/go-gin-prometheus"
)

func LoadRoutes(routes *gin.Engine) {

	// Set Default Middleware
	routes.Use(
		middleware.RequestSizeLimiter(10240),
		middleware.RequestsLogger(),
		middleware.APILoadControl(),
	)

	// Set up default handler for no routes found
	routes.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{"error": "404 - PAGE_NOT_FOUND", "message": "Requested route does not exist"})
	})

	// Prometheus Metrics Collection middleware
	p := ginprometheus.NewPrometheus("gin")
	p.MetricsPath = "/api/v1/metrics"
	p.UseWithAuth(routes, gin.Accounts{"metrics_admin": "metrics_admin"})

	// Register JSON Web Token Middleware
	jwtMiddleware := middleware.JwtConfigGenerate()

	// Short hand declaration for JWT Middleware
	authWare := jwtMiddleware.MiddlewareFunc

	// /api/v1 Routes group and associated handlers
	apiV1 := routes.Group("/api/v1")
	{
		apiV1.POST("/login", jwtMiddleware.LoginHandler)
		apiV1.GET("/refresh-token", jwtMiddleware.RefreshHandler)
		apiV1.GET("/ping", handlers.Ping)
		apiV1.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

		admin := apiV1.Group("/admin").Use(authWare())
		{
			admin.POST("/on-demand-scan", handlers.LaunchAdHocScan)
			admin.POST("/bulk-on-demand-scan", handlers.LaunchBulkAdHocScan)
			admin.GET("/user/:user-id", handlers.GetUser)
			admin.GET("/all-users", handlers.GetAllUsers)
			admin.POST("/user", handlers.CreateUser)
			admin.PATCH("/user/:user-id", handlers.UpdateUser)
			admin.DELETE("/user/:user-id", handlers.DeleteUser)
			admin.GET("/enterprise/:enterprise-id", handlers.GetEnterprise)
			admin.GET("/all-enterprises", handlers.GetAllEnterprises)
			admin.POST("/enterprise", handlers.CreateEnterprise)
			admin.PATCH("/enterprise/:enterprise-id", tempHandler)
			admin.DELETE("/enterprise/:enterprise-id", handlers.DeleteEnterprise)

			admin.GET("/ongoing-scanned-devices", handlers.GetCurrentlyScannedDevices)
		}

		batchAdmin := apiV1.Group("/admin/batch").Use(authWare())
		{
			batchAdmin.POST("/update-all-cisco-sa", handlers.UpdateCiscoOpenVulnSAAll)
			batchAdmin.POST("/cisco-sw-suggested", handlers.AdminGetAnutaDeviceSuggestedSW)
			batchAdmin.POST("/update-smartnet-coverage", handlers.AdminFetchCiscoAMCStatus)
			batchAdmin.POST("/refresh-inventory-cache", handlers.RefreshInventoryCache)
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
			scan.POST("/bulk-anuta-inventory", authWare(), handlers.LaunchAnutaInventoryBulkScan)
		}
		vuln := apiV1.Group("/vulnerabilities").Use(authWare())
		{
			vuln.GET("/cisco-advisory/:cisco-sa", tempHandler)
			vuln.GET("/cve/:cve-id", tempHandler)
			vuln.GET("/device/:device-name", tempHandler)
			vuln.GET("/cisco-published-sa", tempHandler)
			vuln.GET("/summary", tempHandler)
		}
		sshgw := apiV1.Group("/ssh-gateways").Use(authWare())
		{
			sshgw.GET("/all", handlers.GetAllUserSSHGateway)
			sshgw.GET("/gateway/:gw-name", handlers.GetUserSSHGateway)
			sshgw.POST("/gateway", tempHandler)
			sshgw.PATCH("/gateway/:gw-name", tempHandler)
			sshgw.DELETE("/gateway/:gw-name", handlers.DeleteUserSSHGateway)
		}
		devcreds := apiV1.Group("/device-credentials").Use(authWare())
		{
			devcreds.GET("/all", handlers.GetAllUserDeviceCredentials)
			devcreds.GET("/credential/:creds-name", handlers.GetUserDeviceCredentials)
			devcreds.POST("/credential", handlers.CreateUserDeviceCredentials)
			devcreds.PATCH("/credential/:creds-name", handlers.UpdateUserDeviceCredentials)
			devcreds.DELETE("/credential/:creds-name", handlers.DeleteUserDeviceCredentials)
		}

	}

}

func tempHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"test": "ok"})
}
