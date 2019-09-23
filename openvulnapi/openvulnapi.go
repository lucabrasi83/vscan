// Package openvulnapi handles metadata fetching from Cisco PSIRT Openvuln API
package openvulnapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lucabrasi83/vscan/logging"
)

func init() {

	// Disable Init Function when running tests
	for _, arg := range os.Args {
		if strings.Contains(arg, "test") {
			return
		}
	}

	if os.Getenv("VULSCANO_OPENVULN_CLIENT_ID") == "" {
		logging.VSCANLog("fatal", "Environment Variable VULSCANO_OPENVULN_CLIENT_ID is empty!")
	}
	if os.Getenv("VULSCANO_OPENVULN_CLIENT_SECRET") == "" {
		logging.VSCANLog("fatal", "Environment Variable VULSCANO_OPENVULN_CLIENT_ID is empty!")
	}
}

const (
	baseAllVulnURL  = "https://api.cisco.com/security/advisories/all.json"
	grantType       = "client_credentials"
	snToPIDBaseURL  = "https://api.cisco.com/sn2info/v2/identifiers/orderable/serial_numbers/"
	SWSugBaseURL    = "https://api.cisco.com/software/suggestion/v2/suggestions/releases/productIds/"
	snSmartCoverURL = "https://api.cisco.com/sn2info/v2/coverage/summary/serial_numbers/"
)

var (
	clientID        = os.Getenv("VULSCANO_OPENVULN_CLIENT_ID")
	clientSecret    = os.Getenv("VULSCANO_OPENVULN_CLIENT_SECRET")
	ciscoAPIToken   string
	tokenExpiryDate time.Time
)

const (
	shortHTTPReqTimeout = 30 * time.Second
	longHTTPReqTimeout  = 10 * time.Minute
)

type VulnMetadata struct {
	AdvisoryID           string   `json:"advisoryId"`
	AdvisoryTitle        string   `json:"advisoryTitle"`
	FirstPublished       string   `json:"firstPublished"`
	FixedVersions        []string `json:"firstFixed,omitempty"`
	BugID                []string `json:"bugIDs"`
	CVE                  []string `json:"cves"`
	SecurityImpactRating string   `json:"sir"`
	CVSSBaseScore        string   `json:"cvssBaseScore"`
	PublicationURL       string   `json:"publicationUrl"`
}

type VulnMetadataList struct {
	Advisories []VulnMetadata `json:"advisories"`
}

type CiscoSnAPI struct {
	SerialNumbers []struct {
		SrNo             string `json:"sr_no"`
		OrderablePidList []struct {
			OrderablePid string `json:"orderable_pid"`
		} `json:"orderable_pid_list"`
	} `json:"serial_numbers"`
}

type CiscoSWSuggestionAPI struct {
	ProductList []struct {
		Product struct {
			BasePID      string `json:"basePID"`
			MdfID        string `json:"mdfId"`
			ProductName  string `json:"productName"`
			SoftwareType string `json:"softwareType"`
		} `json:"product"`
		Suggestions []struct {
			ID             string `json:"id"`
			IsSuggested    string `json:"isSuggested"`
			ReleaseFormat2 string `json:"releaseFormat2"`
			ReleaseDate    string `json:"releaseDate"`
		} `json:"suggestions"`
	} `json:"productList"`
}

type BearerToken struct {
	Token     string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}

type SmartNetCoverage struct {
	PaginationResponseRecord PaginationResponseRecord `json:"pagination_response_record"`
	SerialNumbers            []SerialNumbers          `json:"serial_numbers"`
}
type PaginationResponseRecord struct {
	LastIndex    int    `json:"last_index"`
	PageIndex    int    `json:"page_index"`
	PageRecords  int    `json:"page_records"`
	SelfLink     string `json:"self_link"`
	Title        string `json:"title"`
	TotalRecords int    `json:"total_records"`
}
type BasePidList struct {
	BasePid string `json:"base_pid"`
}
type OrderablePidList struct {
	ItemDescription string `json:"item_description"`
	ItemPosition    string `json:"item_position"`
	ItemType        string `json:"item_type"`
	OrderablePid    string `json:"orderable_pid"`
	PillarCode      string `json:"pillar_code"`
}
type SerialNumbers struct {
	BasePidList               []BasePidList      `json:"base_pid_list"`
	ContractSiteCustomerName  string             `json:"contract_site_customer_name"`
	ContractSiteAddress1      string             `json:"contract_site_address1"`
	ContractSiteCity          string             `json:"contract_site_city"`
	ContractSiteStateProvince string             `json:"contract_site_state_province"`
	ContractSiteCountry       string             `json:"contract_site_country"`
	CoveredProductLineEndDate string             `json:"covered_product_line_end_date"`
	ID                        string             `json:"id"`
	IsCovered                 string             `json:"is_covered"`
	OrderablePidList          []OrderablePidList `json:"orderable_pid_list"`
	ParentSrNo                string             `json:"parent_sr_no"`
	ServiceContractNumber     string             `json:"service_contract_number"`
	ServiceLineDescr          string             `json:"service_line_descr"`
	SrNo                      string             `json:"sr_no"`
	WarrantyEndDate           string             `json:"warranty_end_date"`
	WarrantyType              string             `json:"warranty_type"`
	WarrantyTypeDescription   string             `json:"warranty_type_description"`
}

func getOpenVulnToken() error {

	tokenReq, err := http.NewRequest("POST",
		"https://cloudsso.cisco.com/as/token.oauth2?grant_type="+grantType+"&client_id="+clientID+
			"&client_secret="+clientSecret, nil)

	if err != nil {
		return fmt.Errorf("error while building request for Cisco openvulnAPI token: %v", err)
	}

	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Set timeout to 5 seconds for HTTP requests
	ctx, cancel := context.WithTimeout(tokenReq.Context(), shortHTTPReqTimeout)
	defer cancel()

	tokenReq = tokenReq.WithContext(ctx)

	tokenRes, err := http.DefaultClient.Do(tokenReq)

	// TODO: Current error exposes full URL with credentials. Need to find a way to obfuscate while still displaying
	// the error returned.
	if err != nil {
		return fmt.Errorf("error while contacting Cisco SSO API: %v", err)
	}

	if tokenRes.StatusCode != http.StatusOK || tokenRes.StatusCode > http.StatusAccepted {
		return errors.New("token request rejected by Cisco SSO API")
	}

	var t BearerToken
	if err := json.NewDecoder(tokenRes.Body).Decode(&t); err != nil {
		return fmt.Errorf("error while serializing into JSON token body into struct: %v", err)
	}

	defer tokenRes.Body.Close()

	ciscoAPIToken = t.Token
	tokenExpiryDate = time.Now().Add(time.Second * time.Duration(t.ExpiresIn))

	return nil
}

// GetAllVulnMetaData will fetch the all vulnerabilities metadata from Cisco openVuln API published by Cisco
// It takes the Cisco Advisory ID as parameter and returns VulnMetadata struct or error
func GetAllVulnMetaData() ([]VulnMetadata, error) {

	url := baseAllVulnURL

	err := checkTokenValidity(time.Now())

	if err != nil {
		return nil, fmt.Errorf("failed to get Bearer token from Cisco openVulnAPI: %v", err)
	}

	vulnMetaReq, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, fmt.Errorf("cannot fetch vulnerability metadata: %v", err)
	}

	vulnMetaReq.Header.Add("Content-Type", "application/json")
	vulnMetaReq.Header.Add("Authorization", "Bearer "+ciscoAPIToken)

	ctx, cancel := context.WithTimeout(vulnMetaReq.Context(), longHTTPReqTimeout)
	defer cancel()

	vulnMetaReq = vulnMetaReq.WithContext(ctx)

	vulnMetaRes, err := http.DefaultClient.Do(vulnMetaReq)

	// TODO: Current error exposes full URL with credentials. Need to find a way to obfuscate while still displaying
	// the error returned.
	if err != nil {
		return nil, fmt.Errorf("error while contacting Cisco openVuln API: %v", err)
	}
	if vulnMetaRes.StatusCode != http.StatusOK || vulnMetaRes.StatusCode > http.StatusAccepted {
		return nil, errors.New("vulnerability metadata request rejected by Cisco openVuln API")
	}

	var v VulnMetadataList
	if err := json.NewDecoder(vulnMetaRes.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("error while serializing into JSON vulnerability body into struct: %v", err)
	}

	defer vulnMetaRes.Body.Close()

	return v.Advisories, nil

}

// GetVulnFixedVersions will fetch the security advisories published for a particular IOS/IOS-XE version
// from Cisco openVuln API
// It will return a pointer to slice of type VulnMetadata which will contain the fixed versions for each advisory
func GetVulnFixedVersions(url string, ver string) ([]VulnMetadata, error) {

	// Construct URL with Cisco IOS/IOS-XE Version requested
	url += ver

	err := checkTokenValidity(time.Now())

	if err != nil {
		return nil, fmt.Errorf("failed to get Bearer token from Cisco openVulnAPI: %v", err)
	}

	vulnMetaReq, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, fmt.Errorf("cannot fetch vulnerability metadata: %v", err)
	}

	vulnMetaReq.Header.Add("Content-Type", "application/json")
	vulnMetaReq.Header.Add("Authorization", "Bearer "+ciscoAPIToken)

	ctx, cancel := context.WithTimeout(vulnMetaReq.Context(), shortHTTPReqTimeout)
	defer cancel()

	vulnMetaReq = vulnMetaReq.WithContext(ctx)

	vulnMetaRes, err := http.DefaultClient.Do(vulnMetaReq)

	// TODO: Current error exposes full URL with credentials. Need to find a way to obfuscate while still displaying
	// the error returned.
	if err != nil {
		return nil, fmt.Errorf("error while contacting Cisco openVuln API: %v", err)
	}
	if vulnMetaRes.StatusCode != http.StatusOK || vulnMetaRes.StatusCode > http.StatusAccepted {
		return nil, errors.New("vulnerability metadata request rejected by Cisco openVuln API with status code" +
			" " + http.StatusText(vulnMetaRes.StatusCode))
	}

	var v VulnMetadataList
	if err := json.NewDecoder(vulnMetaRes.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("error while serializing into JSON vulnerability body into struct: %v", err)
	}

	defer vulnMetaRes.Body.Close()

	return v.Advisories, nil

}

// GetCiscoPID will return the Cisco Product ID from Cisco sn2info API
func GetCiscoPID(sn ...string) (*CiscoSnAPI, error) {

	err := checkTokenValidity(time.Now())

	if err != nil {
		return nil, fmt.Errorf("failed to get Bearer token from Cisco openVulnAPI: %v", err)
	}

	snJoined := strings.Join(sn, ",")

	PIDReq, err := http.NewRequest("GET", snToPIDBaseURL+snJoined, nil)

	if err != nil {
		return nil, fmt.Errorf(
			"error %v while building HTTP Request to Cisco SN2INFO API for serial number(s) %v",
			err, sn)
	}

	PIDReq.Header.Add("Content-Type", "application/json")
	PIDReq.Header.Add("Authorization", "Bearer "+ciscoAPIToken)

	ctx, cancel := context.WithTimeout(PIDReq.Context(), longHTTPReqTimeout)
	defer cancel()

	PIDReq = PIDReq.WithContext(ctx)

	PIDRes, err := http.DefaultClient.Do(PIDReq)

	if err != nil {
		return nil, fmt.Errorf("error %v while contacting CISCO SN2INFO API for serial number %v", err, sn)
	}

	if PIDRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"CISCO SN2INFO API responded with error code: %v while querying serial number(s) %v",
			http.StatusText(PIDRes.StatusCode), sn)
	}

	var p CiscoSnAPI

	if err := json.NewDecoder(PIDRes.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("CISCO SN2INFO API error %v while serializing into JSON body into struct", err)
	}

	defer PIDRes.Body.Close()

	return &p, nil

}

// GetSuggestedSW will return the Recommended Software Versions for each Product ID
func GetCiscoSWSuggestion(pid ...string) (*CiscoSWSuggestionAPI, error) {

	err := checkTokenValidity(time.Now())

	if err != nil {
		return nil, fmt.Errorf("failed to get Bearer token from Cisco openVulnAPI: %v", err)
	}

	pidJoined := strings.Join(pid, ",")

	SWReq, err := http.NewRequest("GET", SWSugBaseURL+pidJoined, nil)

	if err != nil {
		return nil, fmt.Errorf(
			"error %v while building HTTP Request to Cisco Suggested SW API for Product ID's %v",
			err, pid)
	}

	SWReq.Header.Add("Content-Type", "application/json")
	SWReq.Header.Add("Authorization", "Bearer "+ciscoAPIToken)

	ctx, cancel := context.WithTimeout(SWReq.Context(), longHTTPReqTimeout)
	defer cancel()

	SWReq = SWReq.WithContext(ctx)

	SWRes, err := http.DefaultClient.Do(SWReq)

	if err != nil {
		return nil, fmt.Errorf("error %v while contacting CISCO SN2INFO API for Product IDs %v", err, pid)
	}

	if SWRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"CISCO Suggested SW API responded with error code: %v while querying Product IDs %v",
			http.StatusText(SWRes.StatusCode), pid)
	}

	var s CiscoSWSuggestionAPI

	if err := json.NewDecoder(SWRes.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("CISCO suggested Software API error %v while serializing into JSON body into struct", err)
	}

	defer SWRes.Body.Close()

	return &s, nil

}

// GetSmartNetCoverage will return the SmartNet Contract coverage status from Cisco sn2info API
func GetSmartNetCoverage(sn ...string) (*SmartNetCoverage, error) {

	err := checkTokenValidity(time.Now())

	if err != nil {
		return nil, fmt.Errorf("failed to get Bearer token from Cisco openVulnAPI: %v", err)
	}

	snJoined := strings.Join(sn, ",")

	CoverReq, err := http.NewRequest("GET", snSmartCoverURL+snJoined, nil)

	if err != nil {
		return nil, fmt.Errorf(
			"error %v while building HTTP Request to Cisco SmartNet Contract API for Serial Numbers %v", err, sn)
	}

	CoverReq.Header.Add("Content-Type", "application/json")
	CoverReq.Header.Add("Authorization", "Bearer "+ciscoAPIToken)

	ctx, cancel := context.WithTimeout(CoverReq.Context(), longHTTPReqTimeout)
	defer cancel()

	CoverReq = CoverReq.WithContext(ctx)

	CoverRes, err := http.DefaultClient.Do(CoverReq)

	if err != nil {
		return nil, fmt.Errorf(
			"error %v while contacting Cisco SmartNet Coverage API for Serial Numbers %v", err, sn)
	}

	if CoverRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"CISCO SmartNet Coverage API responded with error code: %v while querying for serial numbers %v",
			http.StatusText(CoverRes.StatusCode), sn)
	}

	var p SmartNetCoverage

	if err := json.NewDecoder(CoverRes.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf(
			"CISCO SmartNet Coverage API error %v while serializing into JSON body into struct for serial numbers %v", err, sn)
	}

	defer CoverRes.Body.Close()

	return &p, nil

}

// checkTokenValidity is a helper function that will verify the Bearer Token from Cisco API is still valid.
// If not, we get a new one through getOpenVulnToken function
func checkTokenValidity(now time.Time) error {

	if ciscoAPIToken == "" {
		err := getOpenVulnToken()
		if err != nil {
			return err
		}
	} else if now.After(tokenExpiryDate) {
		err := getOpenVulnToken()
		if err != nil {
			return err
		}
	}
	return nil

}
