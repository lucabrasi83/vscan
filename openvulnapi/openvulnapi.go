// Package openvulnapi handles metadata fetching from Cisco PSIRT Openvuln API
package openvulnapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func init() {
	fmt.Println(os.Getenv("VULSCANO_OPENVULN_CLIENT_ID"))
	if os.Getenv("VULSCANO_OPENVULN_CLIENT_ID") == "" {
		panic("Environment Variable VULSCANO_OPENVULN_CLIENT_ID is empty!")
	}
	if os.Getenv("VULSCANO_OPENVULN_CLIENT_SECRET") == "" {
		panic("Environment Variable VULSCANO_OPENVULN_CLIENT_SECRET is empty!")
	}
}

const grantType    = "client_credentials"
var clientID     =  os.Getenv("VULSCANO_OPENVULN_CLIENT_ID") //"krg7pbhgebanzmqdtjf8bjhn"
var clientSecret =  os.Getenv("VULSCANO_OPENVULN_CLIENT_SECRET") //"SaFzEQC8XvYTy9jUMZuSggws"


type VulnMetadata struct {
	AdvisoryID string `json:"advisoryId"`
	AdvisoryTitle string `json:"advisoryTitle"`
	FirstPublished string `json:"firstPublished"`
	BugID []string `json:"bugIDs"`
	CVE []string `json:"cves"`
	SecurityImpactRating string `json:"sir"`
	CVSSBaseScore string `json:"cvssBaseScore"`
}

type BearerToken struct {
	Token string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int	`json:"expires_in"`
}

func GetOpenVulnToken() (string, error) {

	tokenResp, err := http.Post(
		"https://cloudsso.cisco.com/as/token.oauth2?grant_type="+grantType+"&client_id="+clientID+
			"&client_secret="+clientSecret, "application/x-www-form-urlencoded", nil)

	if err != nil {
		return "", fmt.Errorf("error while fetching Cisco openvulnAPI token: %v", err)
	}

	if tokenResp.StatusCode == http.StatusBadRequest {
		return "", fmt.Errorf("error while fetching Cisco openvulnAPI token: %v", err)
	}

	var t BearerToken
	if err := json.NewDecoder(tokenResp.Body).Decode(&t); err != nil {
		return "", fmt.Errorf("error while serializing into JSON token body into struct: %v", err)
	}

	defer tokenResp.Body.Close()

	return t.Token, nil
}

