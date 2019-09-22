// Package datadiros sets the local disk path for persistency
// init() function in this package is the first to be called when launching Vulscano
// TODO: Find a way not to repeat ourselves with similar purpose init() and GetDataDir() functions
package datadiros

import (
	"os"

	"github.com/lucabrasi83/vscan/logging"
)

func init() {

	// Check for Environment Variable VULSCANO_MODE
	switch os.Getenv("VULSCANO_MODE") {
	case "DEV":
		DataDir, err := os.Getwd()
		if err != nil {
			logging.VSCANLog("fatal",
				"Unable to load current directory: ", err.Error())
		}
		logging.VSCANLog("info",
			"DEV Mode. Setting DataDir to: ", DataDir)

	case "PROD":
		DataDir := "/opt/vscan/data"
		logging.VSCANLog("info",
			"PROD Mode. Setting DataDir to: ", DataDir)
	default:
		logging.VSCANLog("fatal",
			"VULSCANO_MODE environment variable is not set!")
	}

}

func GetDataDir() string {
	if os.Getenv("VULSCANO_MODE") == "DEV" {
		DataDir := "."
		return DataDir
	} else if os.Getenv("VULSCANO_MODE") == "PROD" {
		DataDir := "/opt/vscan/data"
		return DataDir
	}
	return ""
}
