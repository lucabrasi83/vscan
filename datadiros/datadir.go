// Package datadiros sets the local disk path for persistency
// init() function in this package is the first to be called when launching Vulscano
// TODO: Find a way not to repeat ourselves with similar purpose init() and GetDataDir() functions
package datadiros

import (
	_ "github.com/lucabrasi83/vulscano/initializer"
	"github.com/lucabrasi83/vulscano/logging"
	"os"
)

func init() {

	// Check for Environment Variable VULSCANO_MODE
	switch os.Getenv("VULSCANO_MODE") {
	case "DEV":
		DataDir, err := os.Getwd()
		if err != nil {
			logging.VulscanoLog("fatal",
				"Unable to load current directory: ", err.Error())
		}
		logging.VulscanoLog("info",
			"DEV Mode. Setting DataDir to: ", DataDir)

	case "PROD":
		DataDir := "/opt/vulscano/data"
		logging.VulscanoLog("info",
			"PROD Mode. Setting DataDir to: ", DataDir)
	default:
		logging.VulscanoLog("fatal",
			"VULSCANO_MODE environment variable is not set!")
	}

}

func GetDataDir() string {
	if os.Getenv("VULSCANO_MODE") == "DEV" {
		DataDir := "."
		return DataDir
	} else if os.Getenv("VULSCANO_MODE") == "PROD" {
		DataDir := "/opt/vulscano/data"
		return DataDir
	}
	return ""
}
