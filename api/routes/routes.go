package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/api/handlers"
)

func LoadRoutes(routes *gin.Engine) {
	routes.GET("/ping", handlers.Ping)
	routes.GET("/ciscoping", handlers.CiscoPing)
}