package handlers

import "net"

// CiscoSecurityAdvisory represents the JSON payload to be sent to POST /api/v1/ciscosameta
type CiscoSecurityAdvisory struct {
	CiscoAdvisoryID string `json:"cisco_sa" binding:"required"`
}

// Login represents the JSON payload to be sent to POST /api/v1/login
type Login struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// AdHocScanDevice represents the JSON payload to be sent to POST /api/v1/adhocscan
type AdHocScanDevice struct {
	Hostname  string `json:"hostname" binding:"required"`
	IPAddress string `json:"ip" binding:"required"`
	OSType    string `json:"os_type" binding:"required"`
}

// AnutaDeviceScanRequest represents the JSON payload to be sent to POST /api/v1/anuta-inventory-device-scan
type AnutaDeviceScanRequest struct {
	DeviceID string `json:"deviceID" binding:"required"`
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
