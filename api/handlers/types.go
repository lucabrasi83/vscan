package handlers

import (
	"net"
	"time"

	"github.com/lucabrasi83/vscan/openvulnapi"
)

// Login represents the JSON payload to be sent to POST /api/v1/login
type Login struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// CiscoScanDevice struct represents the attributes of a Scanned Cisco Device
// The attributes include the Joval definition URL and the Cisco openVuln API URL
type CiscoScanDevice struct {
	jovalURL    string
	openVulnURL string
}

// Scan Results struct represent the Vulnerability Assessment results for a single device
type ScanResults struct {
	ScanJobID                   string                     `json:"scanJobID"`
	ScanJobStartTime            time.Time                  `json:"scanJobStartTime"`
	ScanJobEndTime              time.Time                  `json:"scanJobEndTime"`
	ScanJobExecutingAgent       string                     `json:"scanJobAgent"`
	ScanDeviceMeanTime          int                        `json:"scanDeviceMeanTimeMsec"`
	TotalVulnerabilitiesFound   int                        `json:"totalVulnerabilitiesFound"`
	TotalVulnerabilitiesScanned int                        `json:"totalVulnerabilitiesScanned"`
	VulnerabilitiesFoundDetails []openvulnapi.VulnMetadata `json:"vulnerabilitiesFoundDetails"`
	ScanLogs                    string                     `json:"-"`
}

// PingAPIResponse struct represents the JSON Body Response for API Health Check
type PingAPIResponse struct {
	ReplyBack       string `json:"ping" example:"I'm Alive"`
	VulscanoVersion string `json:"version" example:"0.2.1"`
	GolangVersion   string `json:"golangRuntime" example:"1.11.5"`
}

// Scan ReportFile represents the JSON report file created for each device by Joval scan
type ScanReportFile struct {
	DeviceName    string                 `json:"fact_friendlyname"`
	ScanStartTime string                 `json:"start_time"`
	ScanEndTime   string                 `json:"end_time"`
	RuleResults   []ScanReportFileResult `json:"rule_results"`
}

// ScanReportFileResult represents the rule_result section of the JSON report file
type ScanReportFileResult struct {
	RuleResult     string                           `json:"rule_result"`
	RuleIdentifier []ScanReportFileResultIdentifier `json:"rule_identifiers"`
}

// ScanReportFileResultIdentifier represents the rule_identifiers section of the JSON report file
type ScanReportFileResultIdentifier struct {
	ResultCiscoSA string `json:"identifier"`
}

// AdHocScanDevice represents the JSON payload to be sent to POST /api/v1/admin/on-demand-scan
type AdHocScanDevice struct {
	Hostname             string `json:"hostname" binding:"required" example:"TCL-IN-MUMBAI-RTR-1"`
	IPAddress            string `json:"ip" binding:"required" example:"10.1.1.1"`
	OSType               string `json:"osType" binding:"required" example:"IOS-XE"`
	CredentialsName      string `json:"credentialsName" binding:"required" example:"MY-TACACS-CREDS"`
	OSVersion            string `json:"osVersion" example:"16.06.04"`
	SSHGateway           string `json:"sshGateway" example:"UKL78-SSH-GW"`
	LogStreamHashRequest string `json:"logStreamHashReq,omitempty"`
}

// AdHocBulkScan represents a slice of AdHocBulkScanDevice struct
// for multiple devices to be scanned in a single container
type AdHocBulkScan struct {
	OSType               string                `json:"osType" binding:"required"`
	SSHGateway           string                `json:"sshGateway"`
	CredentialsName      string                `json:"credentialsName" binding:"required"`
	Devices              []AdHocBulkScanDevice `json:"devices" binding:"required"`
	LogStreamHashRequest string                `json:"logStreamHashReq,omitempty"`
}

type AdHocBulkScanDevice struct {
	Hostname  string `json:"hostname" binding:"required"`
	IPAddress string `json:"ip" binding:"required"`
}

// AnutaDeviceScanRequest represents the JSON payload to be sent to POST /api/v1/scan/anuta-inventory-device
type AnutaDeviceScanRequest struct {
	DeviceID             string `json:"deviceID" binding:"required"`
	CredentialsName      string `json:"credentialsName" binding:"required"`
	LogStreamHashRequest string `json:"logStreamHashReq,omitempty"`
	SSHGateway           string `json:"sshGateway"`
}

type AnutaDeviceBulkScanRequest struct {
	OSType               string                   `json:"osType" binding:"required"`
	SSHGateway           string                   `json:"sshGateway"`
	CredentialsName      string                   `json:"credentialsName" binding:"required"`
	LogStreamHashRequest string                   `json:"logStreamHashReq,omitempty"`
	Devices              []AnutaDeviceScanRequest `json:"devices" binding:"required"`
}

// AnutaDeviceInventory struct represents a device attributes from Anuta NCX inventory
type AnutaDeviceInventory struct {
	DeviceName    string       `json:"deviceName"`
	MgmtIPAddress net.IP       `json:"mgmtIPAddress"`
	Status        string       `json:"status"`
	OSType        string       `json:"OSType"`
	OSVersion     string       `json:"OSVersion"`
	CiscoModel    string       `json:"ciscoModel"`
	Hostname      string       `json:"hostname"`
	SerialNumber  string       `json:"serialNumber,omitempty"`
	RecommendedSW string       `json:"suggestedVersion,omitempty"`
	EnterpriseID  string       `json:"-"`
	ScanResults   *ScanResults `json:"scanResults"`
}

// AnutaBulkScanResults struct represents the response attributes when doing a bulk scan on multiple Anuta inventory
// devices
type AnutaBulkScanResults struct {
	ScanJobID             string                      `json:"scanJobID"`
	ScanJobStartTime      time.Time                   `json:"scanJobStartTime"`
	ScanJobEndTime        time.Time                   `json:"scanJobEndTime"`
	ScanJobExecutingAgent string                      `json:"scanJobAgent"`
	DevicesScannedSuccess []string                    `json:"devicesScannedSuccess"`
	DevicesScannedSkipped []string                    `json:"devicesScannedSkipped"`
	DevicesScannedFailure []string                    `json:"devicesScannedFailure"`
	DevicesScanResults    []AnutaBulkScanResultsChild `json:"devicesScanResults"`
}

type AnutaBulkScanResultsChild struct {
	DeviceName                  string                     `json:"deviceName"`
	MgmtIPAddress               net.IP                     `json:"mgmtIPAddress"`
	Status                      string                     `json:"status"`
	OSType                      string                     `json:"OSType"`
	OSVersion                   string                     `json:"OSVersion"`
	CiscoModel                  string                     `json:"ciscoModel"`
	SerialNumber                string                     `json:"serialNumber,omitempty"`
	Hostname                    string                     `json:"hostname"`
	RecommendedSW               string                     `json:"suggestedVersion,omitempty"`
	EnterpriseID                string                     `json:"-"`
	TotalVulnerabilitiesFound   int                        `json:"totalVulnerabilitiesFound"`
	TotalVulnerabilitiesScanned int                        `json:"totalVulnerabilitiesScanned"`
	ScanDeviceMeanTime          int                        `json:"scanDeviceMeanTimeMsec"`
	VulnerabilitiesFoundDetails []openvulnapi.VulnMetadata `json:"vulnerabilitiesFoundDetails"`
}

type BulkScanResults struct {
	ScanJobID             string              `json:"scanJobID"`
	ScanJobStartTime      time.Time           `json:"scanJobStartTime"`
	ScanJobEndTime        time.Time           `json:"scanJobEndTime"`
	ScanJobExecutingAgent string              `json:"scanJobAgent"`
	DevicesScannedSuccess []string            `json:"devicesScannedSuccess"`
	DevicesScannedFailure []string            `json:"devicesScannedFailure"`
	VulnerabilitiesFound  []BulkScanVulnFound `json:"vulnFoundDetails"`
	ScanLogs              string              `json:"-"`
}

type BulkScanVulnFound struct {
	DeviceName                  string                     `json:"deviceName"`
	ScanDeviceMeanTime          int                        `json:"scanDeviceMeanTimeMsec"`
	TotalVulnerabilitiesFound   int                        `json:"totalVulnerabilitiesFound"`
	TotalVulnerabilitiesScanned int                        `json:"totalVulnerabilitiesScanned"`
	VulnerabilitiesFoundDetails []openvulnapi.VulnMetadata `json:"vulnerabilitiesFoundDetails"`
}

// JwtClaim struct represents the JWTMapClaim type from middleware authjwt package
// It contains user attributes after JWT authorization is successful
type JwtClaim struct {
	Enterprise string
	UserID     string
	Email      string
	Role       string
}

// VulscanoUserCreate struct represents the JSON keys required to be passed by API consumer
// in order to create a new user
type VulscanoUserCreate struct {
	Email      string `json:"email" binding:"required" example:"john@vscan.com"`
	Password   string `json:"password" binding:"required" example:"!Mp0$$ible_2_ReMemBeR"`
	Role       string `json:"role" binding:"required" example:"vulscanouser"`
	Enterprise string `json:"enterpriseID" binding:"required" example:"TCL"`
}

// VulscanoUserUpdate struct represents the JSON keys required to be passed by API consumer
// in order to PATCH an existing user
type VulscanoUserPatch struct {
	Password   string `json:"password" example:"!Mp0$$ible_2_ReMemBeR"`
	Role       string `json:"role" example:"vulscanouser"`
	Enterprise string `json:"enterpriseID" example:"TCL"`
}

// UserSSHGateway struct represents the attributes of a user defined SSH Gateway
type UserSSHGateway struct {
	GatewayName       string
	GatewayIP         net.IP
	GatewayUsername   string
	GatewayPassword   string
	GatewayPrivateKey string
}

// UserSSHGatewayCreate struct represents represents the JSON keys to be passed in order to create a new SSH Gateway
type UserSSHGatewayCreate struct {
	GatewayName       string `json:"gatewayName" binding:"required"`
	GatewayIP         string `json:"gatewayIP" binding:"required"`
	GatewayUsername   string `json:"gatewayUsername" binding:"required"`
	GatewayPassword   string `json:"gatewayPassword"`
	GatewayPrivateKey string `json:"gatewayPrivateKey"`
}

// UserSSHGatewayUpdate struct represents represents the JSON keys to be passed in order to update a SSH Gateway
type UserSSHGatewayUpdate struct {
	GatewayIP         string `json:"gatewayIP"`
	GatewayUsername   string `json:"gatewayUsername"`
	GatewayPassword   string `json:"gatewayPassword"`
	GatewayPrivateKey string `json:"gatewayPrivateKey"`
}

// UserDeviceCredentials struct represents the Device Credentials to connect to a scanned device
type UserDeviceCredentials struct {
	CredentialsName         string
	CredentialsDeviceVendor string
	Username                string
	Password                string
	IOSEnablePassword       string
	PrivateKey              string
}

// UserDeviceCredentialsCreate struct represents the JSON keys to be passed in order to create a new device credential set
type DeviceCredentialsCreate struct {
	CredentialsName         string `json:"credentialsName" binding:"required"`
	CredentialsDeviceVendor string `json:"credentialsDeviceVendor" binding:"required"`
	Username                string `json:"username" binding:"required"`
	Password                string `json:"password"`
	IOSEnablePassword       string `json:"iosEnablePassword"`
	PrivateKey              string `json:"privateKey"`
}

// UserDeviceCredentialsUpdate struct represents the JSON keys to be passed in order to update a new device credential set
type DeviceCredentialsUpdate struct {
	CredentialsName         string `json:"credentialsName"`
	CredentialsDeviceVendor string `json:"credentialsDeviceVendor"`
	Username                string `json:"username"`
	Password                string `json:"password"`
	IOSEnablePassword       string `json:"iosEnablePassword"`
	PrivateKey              string `json:"privateKey"`
}

// EnterpriseCreate struct represents the JSON keys to be passed in order to create a new enterprise
type EnterpriseCreate struct {
	EnterpriseID   string `json:"enterpriseID" binding:"required"`
	EnterpriseName string `json:"enterpriseName" binding:"required"`
}
