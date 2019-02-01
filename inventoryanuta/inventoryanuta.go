package inventoryanuta

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type AnutaAPIDeviceDetails struct {
	DeviceName       string                          `json:"id"`
	MgmtIPAddress    string                          `json:"mgmt-ip-address"`
	Status           string                          `json:"status"`
	OSType           string                          `json:"ostype-string"`
	OSVersion        string                          `json:"os-version"`
	CiscoModel       string                          `json:"device-type"`
	SerialNumber     string                          `json:"serial-number"`
	Hostname         string                          `json:"name"`
	RealIOSXEVersion AnutaIOSXEVersionChildContainer `json:"iosxeversion:iosxe-version,omitempty"`
}

type AnutaIOSXEVersionChildContainer struct {
	IOSXEVersionChildContainer string `json:"version,omitempty"`
}

type AnutaAPIDeviceParent struct {
	Controller *AnutaAPIDeviceDetails `json:"controller:device"`
}

const (
	anutaDeviceFilters = "?fields=id;mgmt-ip-address;status;os-version;" +
		"iosxeversion:iosxe-version/version;ostype-string;device-type;serial-number;name"
)

var (
	anutaNCXHost  = os.Getenv("ANUTA_NCX_HOST")
	anutaBaseAuth = os.Getenv("ANUTA_NCX_BASE64_AUTH")
)

func GetAnutaDevice(dev string) (*AnutaAPIDeviceDetails, error) {

	// Construct API Call URL to query device details
	url := strings.Join([]string{
		"https://",
		anutaNCXHost,
		"/restconf/data/controller:devices/device=",
		dev,
		".json",
		anutaDeviceFilters,
	}, "")

	// Disable HTTP/2 to connect to Anuta NCX API
	tr := &http.Transport{
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	anutaHTTPClient := http.Client{Transport: tr}

	// Construct HTTP Request parameters
	anutaDeviceReq, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, fmt.Errorf("cannot fetch details from Anuta for device %v:%v", dev, err)
	}

	anutaDeviceReq.Header.Add("Content-Type", "application/json")
	anutaDeviceReq.Header.Add("Authorization", "Basic "+anutaBaseAuth)

	ctx, cancel := context.WithTimeout(anutaDeviceReq.Context(), 10*time.Second)
	defer cancel()

	anutaDeviceReq = anutaDeviceReq.WithContext(ctx)

	anutaDeviceRes, err := anutaHTTPClient.Do(anutaDeviceReq)

	if err != nil {
		return nil, fmt.Errorf("error while contacting Anuta NCX API: %v", err)
	}
	if anutaDeviceRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"cannot get device %v details from Anuta NCX API. HTTP Error Code %v",
			dev,
			anutaDeviceRes.Status)
	}

	var v AnutaAPIDeviceParent
	if err := json.NewDecoder(anutaDeviceRes.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("error while serializing struct into JSON body: %v", err)
	}

	defer anutaDeviceRes.Body.Close()

	return (&v).Controller, nil

}
