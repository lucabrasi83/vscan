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
)

//https://play.golang.org/p/sJjy61xyY9M
func init() {
	if os.Getenv("VULSCANO_OPENVULN_CLIENT_ID") == "" {
		panic("Environment Variable VULSCANO_OPENVULN_CLIENT_ID is empty!")
	}
	if os.Getenv("VULSCANO_OPENVULN_CLIENT_SECRET") == "" {
		panic("Environment Variable VULSCANO_OPENVULN_CLIENT_SECRET is empty!")
	}
}

const (
	baseAllVulnURL = "https://api.cisco.com/security/advisories/all.json"
	grantType      = "client_credentials"
	snToPIDBaseURL = "https://api.cisco.com/sn2info/v2/identifiers/orderable/serial_numbers/"
	SWSugBaseURL   = "https://api.cisco.com/software/suggestion/v2/suggestions/releases/productIds/"
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

func getOpenVulnToken() error {

	tokenReq, err := http.NewRequest("POST",
		"https://cloudsso.cisco.com/as/token.oauth2?grant_type="+grantType+"&client_id="+clientID+
			"&client_secret="+clientSecret, nil)

	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		return fmt.Errorf("error while building request for Cisco openvulnAPI token: %v", err)
	}

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
		return nil, fmt.Errorf("cannot fetch Cisco Product ID: %v", err)
	}

	PIDReq.Header.Add("Content-Type", "application/json")
	PIDReq.Header.Add("Authorization", "Bearer "+ciscoAPIToken)

	ctx, cancel := context.WithTimeout(PIDReq.Context(), longHTTPReqTimeout)
	defer cancel()

	PIDReq = PIDReq.WithContext(ctx)

	PIDRes, err := http.DefaultClient.Do(PIDReq)

	if err != nil {
		return nil, fmt.Errorf("error while contacting Cisco API: %v", err)
	}

	if PIDRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sn2info API responded with error code: %v", http.StatusText(PIDRes.StatusCode))
	}

	var p CiscoSnAPI

	if err := json.NewDecoder(PIDRes.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("error while serializing into JSON body into struct: %v", err)
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
		return nil, fmt.Errorf("cannot fetch Cisco Suggested SW: %v", err)
	}

	SWReq.Header.Add("Content-Type", "application/json")
	SWReq.Header.Add("Authorization", "Bearer "+ciscoAPIToken)

	ctx, cancel := context.WithTimeout(SWReq.Context(), longHTTPReqTimeout)
	defer cancel()

	SWReq = SWReq.WithContext(ctx)

	SWRes, err := http.DefaultClient.Do(SWReq)

	if err != nil {
		return nil, fmt.Errorf("error while contacting Cisco API: %v", err)
	}

	if SWRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("swsuggestions API responded with error code: %v", http.StatusText(SWRes.StatusCode))
	}

	var s CiscoSWSuggestionAPI

	if err := json.NewDecoder(SWRes.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("error while serializing into JSON body into struct: %v", err)
	}

	defer SWRes.Body.Close()

	return &s, nil

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
