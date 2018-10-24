// Package openvulnapi handles metadata fetching from Cisco PSIRT Openvuln API
package openvulnapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

func init() {
	if os.Getenv("VULSCANO_OPENVULN_CLIENT_ID") == "" {
		panic("Environment Variable VULSCANO_OPENVULN_CLIENT_ID is empty!")
	}
	if os.Getenv("VULSCANO_OPENVULN_CLIENT_SECRET") == "" {
		panic("Environment Variable VULSCANO_OPENVULN_CLIENT_SECRET is empty!")
	}
}

const (
	baseVulnSaURL    = "https://api.cisco.com/security/advisories/advisory/"
	baseVulnIOSURL   = "https://api.cisco.com/security/advisories/ios.json?version="
	baseVulnIOSXEURL = "https://api.cisco.com/security/advisories/iosxe.json?version="
	grantType        = "client_credentials"
)

var clientID = os.Getenv("VULSCANO_OPENVULN_CLIENT_ID")
var clientSecret = os.Getenv("VULSCANO_OPENVULN_CLIENT_SECRET")

type VulnMetadata struct {
	AdvisoryID           string   `json:"advisoryId"`
	AdvisoryTitle        string   `json:"advisoryTitle"`
	FirstPublished       string   `json:"firstPublished"`
	BugID                []string `json:"bugIDs"`
	CVE                  []string `json:"cves"`
	SecurityImpactRating string   `json:"sir"`
	CVSSBaseScore        string   `json:"cvssBaseScore"`
	PublicationURL       string   `json:"publicationUrl"`
}

type VulnMetadataList struct {
	Advisories *[]VulnMetadata `json:"advisories"`
}

type BearerToken struct {
	Token     string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}

func getOpenVulnToken() (string, error) {

	tokenReq, err := http.NewRequest("POST",
		"https://cloudsso.cisco.com/as/token.oauth2?grant_type="+grantType+"&client_id="+clientID+
			"&client_secret="+clientSecret, nil)

	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		return "", fmt.Errorf("error while building request for Cisco openvulnAPI token: %v", err)
	}

	// Set timeout to 5 seconds for HTTP requests
	ctx, cancel := context.WithTimeout(tokenReq.Context(), 5*time.Second)
	defer cancel()

	tokenReq = tokenReq.WithContext(ctx)

	tokenRes, err := http.DefaultClient.Do(tokenReq)

	// TODO: Current error exposes full URL with credentials. Need to find a way to obfuscate while still displaying
	// the error returned.
	if err != nil {
		return "", fmt.Errorf("error while contacting Cisco SSO API: %v", err)
	}

	if tokenRes.StatusCode != http.StatusOK || tokenRes.StatusCode > http.StatusAccepted {
		return "", errors.New("token request rejected by Cisco SSO API")
	}

	var t BearerToken
	if err := json.NewDecoder(tokenRes.Body).Decode(&t); err != nil {
		return "", fmt.Errorf("error while serializing into JSON token body into struct: %v", err)
	}

	defer tokenRes.Body.Close()

	return t.Token, nil
}

// GetVulnMetaData will fetch the vulnerability metadata from Cisco openVuln API
// It takes the Cisco Advisory ID as parameter and returns VulnMetadata struct or error
func GetVulnMetaData(sa string) (*[]VulnMetadata, error) {

	url := baseVulnSaURL + sa + ".json"

	token, err := getOpenVulnToken()

	if err != nil {
		return nil, fmt.Errorf("cannot fetch vulnerability metadata: %v", err)
	}

	vulnMetaReq, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, fmt.Errorf("cannot fetch vulnerability metadata: %v", err)
	}

	vulnMetaReq.Header.Add("Content-Type", "application/json")
	vulnMetaReq.Header.Add("Authorization", "Bearer "+token)

	ctx, cancel := context.WithTimeout(vulnMetaReq.Context(), 5*time.Second)
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

	return (&v).Advisories, nil

}
