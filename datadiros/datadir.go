// Package datadiros sets the local disk path for persistency
// TODO: Find a way not to repeat ourselves with similar purpose init() and GetDataDir() functions
package datadiros

import (
	"log"
	"os"
)

func init() {
	// Check for Environment Variable VULSCANO_MODE
	switch os.Getenv("VULSCANO_MODE") {
	case "DEV":
		DataDir, err := os.Getwd()
		if err != nil {
			log.Fatalln("Unable to load current directory:", err.Error())
		}
		log.Println("DEV Mode. Setting DataDir to:", DataDir)
	case "PROD":
		DataDir := "/opt/vulscano/data"
		log.Println("PROD Mode. Setting DataDir to:", DataDir)
	default:
		log.Fatalln("VULSCANO_MODE environment variable is not set!")
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
