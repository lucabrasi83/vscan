package handlers

import "net"

// Login represents the JSON payload to be sent to POST /api/v1/login
type Login struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// AdHocScanDevice represents the JSON payload to be sent to POST /api/v1/admin/on-demand-scan
type AdHocScanDevice struct {
	Hostname  string `json:"hostname" binding:"required"`
	IPAddress string `json:"ip" binding:"required"`
	OSType    string `json:"os_type" binding:"required"`
	OSVersion string `json:"os_version"`
}

// AdHocBulkScan represents a slice of AdHocScanDevice struct for multiple devices to be scanned in a single container
type AdHocBulkScan struct {
	Devices *[]AdHocScanDevice `json:"devices" binding:"required"`
}

// AnutaDeviceScanRequest represents the JSON payload to be sent to POST /api/v1/scan/anuta-inventory-device
type AnutaDeviceScanRequest struct {
	DeviceID string `json:"deviceID" binding:"required"`
}

type AnutaDeviceBulkScanRequest struct {
	Devices *[]AnutaDeviceScanRequest `json:"devices" binding:"required"`
}

// AnutaDeviceInventory struct represents a device attributes from Anuta NCX inventory
type AnutaDeviceInventory struct {
	DeviceName    string       `json:"deviceName"`
	MgmtIPAddress net.IP       `json:"mgmtIPAddress"`
	Status        string       `json:"status"`
	OSType        string       `json:"OSType"`
	OSVersion     string       `json:"OSVersion"`
	CiscoModel    string       `json:"ciscoModel"`
	EnterpriseID  string       `json:"-"`
	ScanResults   *ScanResults `json:",omitempty"`
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
