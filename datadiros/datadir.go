// Package datadiros sets the local disk path for persistency
// init() function in this package is the first to be called when launching Vulscano
// TODO: Find a way not to repeat ourselves with similar purpose init() and GetDataDir() functions
package datadiros

import (
	"os"
	"strings"

	"github.com/lucabrasi83/vscan/logging"
)

func init() {

	// Disable Init Function when running tests
	for _, arg := range os.Args {
		if strings.Contains(arg, "test") {
			return
		}
	}

	// Check for Environment Variable VSCAN_MODE
	switch os.Getenv("VSCAN_MODE") {
	case "DEV":
		DataDir, err := os.Getwd()
		if err != nil {
			logging.VSCANLog("fatal",
				"Unable to load current directory: %v", err)
		}
		logging.VSCANLog("info",
			"DEV Mode. Setting DataDir to: %v", DataDir)

	case "PROD":
		DataDir := "/opt/vscan/data"
		logging.VSCANLog("info",
			"PROD Mode. Setting DataDir to: %v", DataDir)
	default:
		logging.VSCANLog("fatal",
			"VSCAN_MODE environment variable is not set!")
	}

}

func GetDataDir() string {
	if os.Getenv("VSCAN_MODE") == "DEV" {
		DataDir := "."
		return DataDir
	} else if os.Getenv("VSCAN_MODE") == "PROD" {
		DataDir := "/opt/vscan/data"
		return DataDir
	}
	return ""
}
