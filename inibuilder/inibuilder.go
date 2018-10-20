// Package inibuilder handles creation of config.ini file for Joval Scan jobs.
// Based on scan job inputs in REST API request body, it will dynamically generate ini sections for:
//  - Target Devices Hostname and IP Address
//  - Log folder unique per scan job ID
//  - Reports folder unique per scan job ID
package inibuilder

import (
	"fmt"
	"gopkg.in/ini.v1"
	"os"
)

// Skeleton Struct to reflect from config.ini
type Skeleton struct {
	Benchmark
	Logs
}

// Benchmark Section Struct in config.ini
type Benchmark struct {
	Profile      string `ini:"profile"`
	Source       string `ini:"source"`
	XccdfID      string `ini:"xccdf_id"`
	XccdfVersion int    `ini:"xccdf_version"`
}

// Logs Section Struct in config.ini
type Logs struct {
	ExportDir string 		`ini:"export.dir"`
	Level	string			`ini:"level"`
	OutputExtension	string	`ini:"output.extension"`

}

// BuildIni generates config.ini file per scan jobs.
// The config.ini file is placed in tmp/<scan-job-id>/ folder by default
// It returns any error encountered during the config.ini file generation
func BuildIni(jobID string, dev map[string]string) (err error) {


	// Starts with baseline ini file
	cfg, err := ini.Load([]byte(`[Report: JSON]
										input.type = xccdf_results
										output.extension = json 
										transform.file = ./tools/arf_xccdf_results_to_json_events.xsl
										[Credential: ssh-cisco]
										ios_enable_password = cisco
										password = cisco
										type = SSH
										username = cisco`))
	if err != nil {
		return fmt.Errorf("error while loading default ini content for job ID %v: %v", jobID, err)
	}


	secSkeleton := &Skeleton{
		Benchmark{
			Profile:      "xccdf_org.joval_profile_all_rules",
			XccdfID:      "xccdf_org.joval_benchmark_generated",
			XccdfVersion: 0,
		},
		Logs{
			ExportDir:	"./logs/" + jobID,
			Level:	"warning",
			OutputExtension:".log",
		},
	}

	if err = cfg.ReflectFrom(secSkeleton); err != nil {
		return fmt.Errorf("error while reflecting struct into config.ini: %v", err)
	}

	// Continue INI building in separate function for dynamic parameters
	if err = dynaIniGen(cfg, jobID, dev); err != nil {
		return fmt.Errorf("error while generating dynamic parameters for config.ini: %v", err)
	}


	// Assigns directory name per scan job ID
	dir := "tmp/" + jobID

	// Check whether the directory to be created already exists. If not, we create it with Unix permission 0755
	if _, errDirNotExist := os.Stat(dir); os.IsNotExist(errDirNotExist) {
		if errCreateDir := os.MkdirAll(dir, 0750); errCreateDir!= nil {
			return fmt.Errorf("error while creating directory for job ID %v: %v", jobID, errCreateDir)
		}
	}
	iniFile, err := os.Create(dir + "/config.ini")
	if err != nil {
		return fmt.Errorf("error while saving config.ini for job ID %v: %v", jobID, err)
	}

	// Defer Named return when closing config.ini file to capture any error
	defer func() {
		if errIniClose := iniFile.Close(); errIniClose != nil {
			err = errIniClose
		}
	}()

	if err := cfg.SaveTo(dir + "/config.ini"); err != nil {
		return fmt.Errorf("error while saving config.ini for job ID %v: %v", jobID, err)
	}

	return nil
}


// dynaIniGen generates the remainder of the config.ini file for dynamic sections and key/value pairs
func dynaIniGen(cfg *ini.File, jobID string, dev map[string]string) error {

	_, err := cfg.Section("Report: JSON").NewKey("export.dir", "./reports/" +jobID)

	if err != nil {
		return fmt.Errorf("Error When Setting Reports Directory In Config.ini: %v ", err)
	}

	for k, v := range dev {
		devSection, err := cfg.NewSection("Target: " + k )

		if err != nil {
			return fmt.Errorf("Error When Setting Device Section In Config.ini: %v ", err)
		}
		_, err = devSection.NewKey("credential", "ssh-cisco")

		if err != nil {
			return fmt.Errorf("Error When Setting Credential key In Config.ini: %v ", err)
		}
		_, err = devSection.NewKey("host", v)

		if err != nil {
			return fmt.Errorf("Error When Setting Host key In Config.ini: %v ", err)
		}
	}

	return nil

}