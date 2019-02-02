// File inibuilder handles creation of config.ini file for Joval Scan jobs.
// Based on scan job inputs in REST API request body, it will dynamically generate ini sections for:
//  - Target Devices Hostname and IP Address
//  - Log folder unique per scan job ID
//  - Reports folder unique per scan job ID
package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-ini/ini"
	"github.com/lucabrasi83/vulscano/datadiros"
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
	ExportDir       string `ini:"export.dir"`
	Level           string `ini:"level"`
	OutputExtension string `ini:"output.extension"`
}

// BuildIni generates config.ini file per scan jobs.
// The config.ini file is placed in tmp/<scan-job-id>/ folder by default
// It returns any error encountered during the config.ini file generation
func BuildIni(jobID string, dev []map[string]string, jovalSource string, sshGW *UserSSHGateway,
	creds *UserDeviceCredentials) (err error) {

	// Starts with baseline ini file
	cfg, err := ini.Load(
		[]byte(
			`[Report: JSON]
		input.type = xccdf_results
		output.extension = json 
		transform.file =` + filepath.FromSlash(
				"/opt/jovaldata/tools/arf_xccdf_results_to_json_events.xsl")))

	if err != nil {
		return fmt.Errorf("error while loading default ini content for job ID %v: %v", jobID, err)
	}

	// Add Device Credentials sections details
	var credsName string
	if (*creds).CredentialsName != "" {

		credsName = (*creds).CredentialsName
		err = buildDeviceCredentialsSections(cfg, creds)

		if err != nil {
			return err
		}
	}

	// Add SSH Gateway sections details if a gateway is specified to UserSSHGateway is not nil
	var sshGWName string
	if (*sshGW).GatewayName != "" {

		sshGWName = (*sshGW).GatewayName
		err = buildSSHGatewaySections(cfg, sshGW)

		if err != nil {
			return err
		}

	}

	secSkeleton := &Skeleton{
		Benchmark{
			Profile:      "xccdf_org.joval_profile_all_rules",
			Source:       jovalSource,
			XccdfID:      "xccdf_org.joval_benchmark_generated",
			XccdfVersion: 0,
		},
		Logs{
			ExportDir:       filepath.FromSlash("./logs/jobs/" + jobID),
			Level:           "info",
			OutputExtension: ".log",
		},
	}

	if err = cfg.ReflectFrom(secSkeleton); err != nil {
		return fmt.Errorf("error while reflecting struct into config.ini: %v", err)
	}

	// Continue INI building in separate function for dynamic parameters
	if err = dynaIniGen(cfg, jobID, dev, sshGWName, credsName); err != nil {
		return fmt.Errorf("error while generating dynamic parameters for config.ini: %v", err)
	}

	// Assigns directory name per scan job ID
	dir := filepath.FromSlash(datadiros.GetDataDir() + "/jobconfig/" + jobID)

	// Check whether the directory to be created already exists. If not, we create it with Unix permission 0755
	if _, errDirNotExist := os.Stat(dir); os.IsNotExist(errDirNotExist) {
		if errCreateDir := os.MkdirAll(dir, 0750); errCreateDir != nil {
			return fmt.Errorf("error while creating directory for job ID %v: %v", jobID, errCreateDir)
		}
	}

	iniFile, err := os.Create(filepath.FromSlash(datadiros.GetDataDir() + "/jobconfig/" + jobID + "/config.ini"))
	if err != nil {
		return fmt.Errorf("error while saving config.ini for job ID %v: %v", jobID, err)
	}

	// Defer Named return when closing config.ini file to capture any error
	defer func() {
		if errIniClose := iniFile.Close(); errIniClose != nil {
			err = errIniClose
		}
	}()

	// Save the generated config.ini in jobconfig/JobID/ folder
	if err := cfg.SaveTo(
		filepath.FromSlash(datadiros.GetDataDir() + "/jobconfig/" + jobID + "/config.ini")); err != nil {
		return fmt.Errorf("error while saving config.ini for job ID %v: %v", jobID, err)
	}

	return nil
}

func buildSSHGatewaySections(cfg *ini.File, sshGW *UserSSHGateway) error {

	sshGWCredSec, err := cfg.NewSection("Credential: " + "ssh-gateway")

	if err != nil {
		return fmt.Errorf("Error When Setting SSH Gateway Credentials section in Config.ini: %v ", err)
	}

	_, err = sshGWCredSec.NewKey("type", "SSH")

	if err != nil {
		return fmt.Errorf("Error When Setting SSH Gateway Credentials Type key in Config.ini: %v ", err)
	}
	_, err = sshGWCredSec.NewKey("username", (*sshGW).GatewayUsername)

	if err != nil {
		return fmt.Errorf("Error When Setting SSH Gateway Username key in Config.ini: %v ", err)
	}

	if (*sshGW).GatewayPassword != "" {
		_, err = sshGWCredSec.NewKey("password", (*sshGW).GatewayPassword)

		if err != nil {
			return fmt.Errorf("Error When Setting SSH Gateway Password key in Config.ini: %v ", err)
		}
	}

	if (*sshGW).GatewayPrivateKey != "" {

		// Format SSH Private Key to comply with Joval ini format
		pvKeyJovalFormat := strings.Replace((*sshGW).GatewayPrivateKey, "\n", "\\\r", -1)

		_, err := sshGWCredSec.NewKey("private_key", pvKeyJovalFormat)

		if err != nil {
			return fmt.Errorf("Error When Setting SSH Gateway Private Key in Config.ini: %v ", err)
		}

	}

	sshGwSec, err := cfg.NewSection("Gateway: " + (*sshGW).GatewayName)

	if err != nil {
		return fmt.Errorf("Error When Setting SSH Gateway section in Config.ini: %v ", err)
	}

	_, err = sshGwSec.NewKey("host", (*sshGW).GatewayIP.String())

	if err != nil {
		return fmt.Errorf("Error When Setting SSH Gateway IP key in Config.ini: %v ", err)
	}

	_, err = sshGwSec.NewKey("credential", "ssh-gateway")

	if err != nil {
		return fmt.Errorf("Error When Setting SSH Gateway Credentials key in Config.ini: %v ", err)
	}

	return nil

}

func buildDeviceCredentialsSections(cfg *ini.File, creds *UserDeviceCredentials) error {

	deviceCredSec, err := cfg.NewSection("Credential: " + (*creds).CredentialsName)

	if err != nil {
		return fmt.Errorf("Error When Setting SSH Device Credentials section in Config.ini: %v ", err)
	}

	_, err = deviceCredSec.NewKey("type", "SSH")

	if err != nil {
		return fmt.Errorf("Error When Setting SSH Device Credentials Type key in Config.ini: %v ", err)
	}
	_, err = deviceCredSec.NewKey("username", (*creds).Username)

	if err != nil {
		return fmt.Errorf("Error When Setting SSH Device Username key in Config.ini: %v ", err)
	}

	if (*creds).Password != "" {
		_, err = deviceCredSec.NewKey("password", (*creds).Password)

		if err != nil {
			return fmt.Errorf("Error When Setting SSH Device Password key in Config.ini: %v ", err)
		}
	}

	if (*creds).CredentialsDeviceVendor == "CISCO" && (*creds).IOSEnablePassword != "" {
		_, err = deviceCredSec.NewKey("ios_enable_password", (*creds).IOSEnablePassword)

		if err != nil {
			return fmt.Errorf("Error When Setting SSH Device IOS Enable Password key in Config.ini: %v ", err)
		}
	}

	if (*creds).PrivateKey != "" {

		// Format SSH Private Key to comply with Joval ini format
		pvKeyJovalFormat := strings.Replace((*creds).PrivateKey, "\n", "\\\r", -1)

		_, err := deviceCredSec.NewKey("private_key", pvKeyJovalFormat)

		if err != nil {
			return fmt.Errorf("Error When Setting SSH Device Private Key in Config.ini: %v ", err)
		}

	}

	return nil

}

// dynaIniGen generates the remainder of the config.ini file for dynamic sections and key/value pairs
func dynaIniGen(cfg *ini.File, jobID string, dev []map[string]string, sshGWName string, credsName string) error {

	_, err := cfg.Section(
		"Report: JSON").NewKey("export.dir", filepath.FromSlash("./reports/"+jobID))

	if err != nil {
		return fmt.Errorf("Error When Setting Reports Directory In Config.ini: %v ", err)
	}
	// Loop through devices slice to access the map and build config.ini [Target] section(s)
	for idx := range dev {
		devSection, err := cfg.NewSection("Target: " + dev[idx]["hostname"])

		if err != nil {
			return fmt.Errorf("Error When Setting Device Section In Config.ini: %v ", err)
		}
		_, err = devSection.NewKey("credential", credsName)

		if err != nil {
			return fmt.Errorf("Error When Setting Credential key In Config.ini: %v ", err)
		}
		_, err = devSection.NewKey("host", dev[idx]["ip"])

		if err != nil {
			return fmt.Errorf("Error When Setting Host key In Config.ini: %v ", err)
		}

		// Add SSH Gateway Name if not empty string
		if sshGWName != "" {
			_, err = devSection.NewKey("gateway", sshGWName)

			if err != nil {
				return fmt.Errorf("Error When Setting gateway key In Config.ini: %v ", err)
			}
		}
	}

	return nil

}
