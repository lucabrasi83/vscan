// Package routes handles registration of API endpoints for Gin framework.
package routes

import (
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vscan/api/handlers"
	"github.com/lucabrasi83/vscan/api/middleware"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/swaggo/gin-swagger/swaggerFiles"
	ginprometheus "github.com/zsais/go-gin-prometheus"
)

func LoadRoutes(routes *gin.Engine) {

	// CORS Config
	corsMiddleware := cors.New(cors.Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"PUT", "PATCH", "GET", "POST", "DELETE"},
		AllowHeaders:    []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:   []string{"Content-Length"},
		MaxAge:          12 * time.Hour,
		AllowWebSockets: true,
	})

	// Set Default Middleware
	routes.Use(
		middleware.RequestSizeLimiter(10240),
		middleware.RequestsLogger(),
		middleware.APILoadControl(),
		corsMiddleware,
	)

	// Set up default handler for no routes found
	routes.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{"error": "HTTP Error 404 - API route requested does not exist",
			"message": "Requested route does not exist"})
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
		admin := apiV1.Group("/admin").Use(authWare())
		{

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

		devices := apiV1.GET("/devices").Use(authWare())
		{
			devices.GET("/devices/all", handlers.GetAllInventoryDevices)
			devices.GET("/devices/search", handlers.SearchInventoryDevices)
			devices.DELETE("/devices/device", handlers.DeleteInventoryDevices)
		}

		scan := apiV1.Group("/scan").Use(authWare())
		{
			scan.POST("/anuta-inventory-device", authWare(), handlers.LaunchAnutaInventoryScan)
			scan.POST("/bulk-anuta-inventory", authWare(), handlers.LaunchAnutaInventoryBulkScan)
			scan.POST("/on-demand-scan", handlers.LaunchAdHocScan)
			scan.POST("/bulk-on-demand-scan", handlers.LaunchBulkAdHocScan)
		}
		vuln := apiV1.Group("/vulnerabilities").Use(authWare())
		{
			vuln.GET("/cisco-advisory/:cisco-sa", handlers.GetSAVulnAffectingDevice)
			vuln.GET("/cve/:cve-id", handlers.GetCVEVulnAffectingDevice)
			vuln.GET("/device/:device-name", handlers.GetAllVulnAffectingDevice)
			vuln.GET("/device/:device-name/history", handlers.GetVulnDeviceHistory)
			vuln.GET("/cisco-published-sa", tempHandler)
			vuln.GET("/summary", tempHandler)
		}
		sshgw := apiV1.Group("/ssh-gateways").Use(authWare())
		{
			sshgw.GET("/all", handlers.GetAllUserSSHGateway)
			sshgw.GET("/gateway/:gw-name", handlers.GetUserSSHGateway)
			sshgw.POST("/gateway", tempHandler)
			sshgw.PATCH("/gateway/:gw-name", tempHandler)
			sshgw.DELETE("/gateway", handlers.DeleteUserSSHGateway)
		}
		devcreds := apiV1.Group("/device-credentials").Use(authWare())
		{
			devcreds.GET("/all", handlers.GetAllUserDeviceCredentials)
			devcreds.GET("/credential/:creds-name", handlers.GetUserDeviceCredentials)
			devcreds.POST("/credential", handlers.CreateUserDeviceCredentials)
			devcreds.PATCH("/credential/:creds-name", handlers.UpdateUserDeviceCredentials)
			devcreds.DELETE("/credential", handlers.DeleteUserDeviceCredentials)
		}
		docs := apiV1.Group("/docs")
		{
			docs.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		}
		jobs := apiV1.Group("/jobs").Use(authWare())
		{
			jobs.GET("/ws", handlers.ServeWs)

		}

	}

}

func tempHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"test": "ok"})
}
