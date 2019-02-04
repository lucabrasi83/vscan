package handlers

import (
	"net"
	"time"

	"github.com/lucabrasi83/vulscano/openvulnapi"
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
	ScanJobID                   string                      `json:"scanJobID"`
	ScanJobStartTime            time.Time                   `json:"scanJobStartTime"`
	ScanJobEndTime              time.Time                   `json:"scanJobEndTime"`
	ScanDeviceMeanTime          int                         `json:"scanDeviceMeanTimeMsec"`
	TotalVulnerabilitiesFound   int                         `json:"totalVulnerabilitiesFound"`
	TotalVulnerabilitiesScanned int                         `json:"totalVulnerabilitiesScanned"`
	VulnerabilitiesFoundDetails []*openvulnapi.VulnMetadata `json:"vulnerabilitiesFoundDetails"`
}

// PingAPIResponse struct represents the JSON Body Response for API Health Check
type PingAPIResponse struct {
	ReplyBack       string `json:"pong"`
	VulscanoVersion string `json:"version"`
	GolangVersion   string `json:"golangRuntime"`
}

// Scan ReportFile represents the JSON report file created for each device by Joval scan
type ScanReportFile struct {
	DeviceName    string                  `json:"fact_friendlyname"`
	ScanStartTime string                  `json:"start_time"`
	ScanEndTime   string                  `json:"end_time"`
	RuleResults   []*ScanReportFileResult `json:"rule_results"`
}

// ScanReportFileResult represents the rule_result section of the JSON report file
type ScanReportFileResult struct {
	RuleResult     string                            `json:"rule_result"`
	RuleIdentifier []*ScanReportFileResultIdentifier `json:"rule_identifiers"`
}

// ScanReportFileResultIdentifier represents the rule_identifiers section of the JSON report file
type ScanReportFileResultIdentifier struct {
	ResultCiscoSA string `json:"identifier"`
}

// AdHocScanDevice represents the JSON payload to be sent to POST /api/v1/admin/on-demand-scan
type AdHocScanDevice struct {
	Hostname        string `json:"hostname" binding:"required"`
	IPAddress       string `json:"ip" binding:"required"`
	OSType          string `json:"osType" binding:"required"`
	CredentialsName string `json:"credentialsName" binding:"required"`
	OSVersion       string `json:"osVersion"`
	SSHGateway      string `json:"sshGateway"`
}

// AdHocBulkScan represents a slice of AdHocBulkScanDevice struct for multiple devices to be scanned in a single container
type AdHocBulkScan struct {
	OSType          string                 `json:"osType" binding:"required"`
	SSHGateway      string                 `json:"sshGateway"`
	CredentialsName string                 `json:"credentialsName" binding:"required"`
	Devices         []*AdHocBulkScanDevice `json:"devices" binding:"required"`
}

type AdHocBulkScanDevice struct {
	Hostname  string `json:"hostname" binding:"required"`
	IPAddress string `json:"ip" binding:"required"`
}

// AnutaDeviceScanRequest represents the JSON payload to be sent to POST /api/v1/scan/anuta-inventory-device
type AnutaDeviceScanRequest struct {
	DeviceID        string `json:"deviceID" binding:"required"`
	CredentialsName string `json:"credentialsName" binding:"required"`
	SSHGateway      string `json:"sshGateway"`
}

type AnutaDeviceBulkScanRequest struct {
	OSType          string                    `json:"osType" binding:"required"`
	SSHGateway      string                    `json:"sshGateway"`
	CredentialsName string                    `json:"credentialsName" binding:"required"`
	Devices         []*AnutaDeviceScanRequest `json:"devices" binding:"required"`
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
	ScanJobID             string                       `json:"scanJobID"`
	ScanJobStartTime      time.Time                    `json:"scanJobStartTime"`
	ScanJobEndTime        time.Time                    `json:"scanJobEndTime"`
	DevicesScannedSuccess []string                     `json:"devicesScannedSuccess"`
	DevicesScannedSkipped []string                     `json:"devicesScannedSkipped"`
	DevicesScannedFailure []string                     `json:"devicesScannedFailure"`
	DevicesScanResults    []*AnutaBulkScanResultsChild `json:"devicesScanResults"`
}

type AnutaBulkScanResultsChild struct {
	DeviceName                  string                      `json:"deviceName"`
	MgmtIPAddress               net.IP                      `json:"mgmtIPAddress"`
	Status                      string                      `json:"status"`
	OSType                      string                      `json:"OSType"`
	OSVersion                   string                      `json:"OSVersion"`
	CiscoModel                  string                      `json:"ciscoModel"`
	SerialNumber                string                      `json:"serialNumber,omitempty"`
	Hostname                    string                      `json:"hostname"`
	RecommendedSW               string                      `json:"suggestedVersion,omitempty"`
	EnterpriseID                string                      `json:"-"`
	TotalVulnerabilitiesFound   int                         `json:"totalVulnerabilitiesFound"`
	TotalVulnerabilitiesScanned int                         `json:"totalVulnerabilitiesScanned"`
	ScanDeviceMeanTime          int                         `json:"scanDeviceMeanTimeMsec"`
	VulnerabilitiesFoundDetails []*openvulnapi.VulnMetadata `json:"vulnerabilitiesFoundDetails"`
}

type BulkScanResults struct {
	ScanJobID             string               `json:"scanJobID"`
	ScanJobStartTime      time.Time            `json:"scanJobStartTime"`
	ScanJobEndTime        time.Time            `json:"scanJobEndTime"`
	DevicesScannedSuccess []string             `json:"devicesScannedSuccess"`
	DevicesScannedFailure []string             `json:"devicesScannedFailure"`
	VulnerabilitiesFound  []*BulkScanVulnFound `json:"vulnFoundDetails"`
}

type BulkScanVulnFound struct {
	DeviceName                  string                      `json:"deviceName"`
	ScanDeviceMeanTime          int                         `json:"scanDeviceMeanTimeMsec"`
	TotalVulnerabilitiesFound   int                         `json:"totalVulnerabilitiesFound"`
	TotalVulnerabilitiesScanned int                         `json:"totalVulnerabilitiesScanned"`
	VulnerabilitiesFoundDetails []*openvulnapi.VulnMetadata `json:"vulnerabilitiesFoundDetails"`
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
	Email      string `json:"email" binding:"required"`
	Password   string `json:"password" binding:"required"`
	Role       string `json:"role" binding:"required"`
	Enterprise string `json:"enterpriseID" binding:"required"`
}

// VulscanoUserUpdate struct represents the JSON keys required to be passed by API consumer
// in order to PATCH an existing user
type VulscanoUserPatch struct {
	Password   string `json:"password"`
	Role       string `json:"role"`
	Enterprise string `json:"enterpriseID"`
}

// UserSSHGateway struct represents the attributes of a user defined SSH Gateway
type UserSSHGateway struct {
	GatewayName       string
	GatewayIP         net.IP
	GatewayUsername   string
	GatewayPassword   string
	GatewayPrivateKey string
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
