package middleware

import (
	"net/http"
	"runtime"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/shirou/gopsutil/load"
)

// maxLoadLimit represents the threshold at which we abort the Request due to high system load
// By default value is set at 70% for 5 minutes Average Load
const maxLoadLimit = 0.7

// APILoadControl is a Gin middleware to ensure sufficient resources are available before performing
// a Vulnerability Assessment Job.
// The middleware calculates the current LoadAvg 5 minutes from the operating system and divides by the number of
// available CPU cores. If the result is higher than 0.7 (or system load is currently at 70% capacity),
// the request is aborted
func APILoadControl() gin.HandlerFunc {

	// Number of CPU cores available
	numCPU := runtime.NumCPU()

	// System Load averages for 1 minute, 5 minutes, 15 minutes
	maxLoadAverages, _ := load.Avg()

	// Current 1 minute System Load Average
	currentLoad := maxLoadAverages.Load5

	// Maximum Load tolerated below must be below 0.7
	maxLoad := currentLoad / float64(numCPU)

	return func(c *gin.Context) {

		if maxLoad >= maxLoadLimit {
			logging.VulscanoLog("error",
				"Request from "+c.ClientIP()+" rejected due to high system load.",
				" Current 1 minute Average System Load at "+strconv.FormatFloat(currentLoad, 'f', 2, 64),
			)
			c.Header("connection", "close")
			c.JSON(http.StatusBadGateway, gin.H{"error": "system is currently under heavy load. Please retry later."})
			c.Abort()
		} else {

			c.Next()
		}
	}

}