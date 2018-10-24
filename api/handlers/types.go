package handlers

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
