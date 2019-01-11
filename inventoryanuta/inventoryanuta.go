package inventoryanuta

import (
	"context"
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
	RealIOSXEVersion AnutaIOSXEVersionChildContainer `json:"iosxeversion:iosxe-version,omitempty"`
}

type AnutaIOSXEVersionChildContainer struct {
	IOSXEVersionChildContainer string `json:"version,omitempty"`
}

type AnutaAPIDeviceParent struct {
	Controller *AnutaAPIDeviceDetails `json:"controller:device"`
}

// TODO: Replace with Environment Variables
const (
	anutaDeviceFilters = "?fields=id;mgmt-ip-address;status;os-version;" +
		"				  iosxeversion:iosxe-version/version;ostype-string;device-type"
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

	anutaDeviceReq, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, fmt.Errorf("cannot fetch details from Anuta for device %v:%v", dev, err)
	}

	anutaDeviceReq.Header.Add("Content-Type", "application/json")
	anutaDeviceReq.Header.Add("Authorization", "Basic "+anutaBaseAuth)

	ctx, cancel := context.WithTimeout(anutaDeviceReq.Context(), 10*time.Second)
	defer cancel()

	anutaDeviceReq = anutaDeviceReq.WithContext(ctx)

	anutaDeviceRes, err := http.DefaultClient.Do(anutaDeviceReq)

	if err != nil {
		return nil, fmt.Errorf("error while contacting Anuta NCX API: %v", err)
	}
	if anutaDeviceRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device %v not found in Anuta NCX Inventory", dev)
	}

	var v AnutaAPIDeviceParent
	if err := json.NewDecoder(anutaDeviceRes.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("error while serializing struct into JSON body: %v", err)
	}

	defer anutaDeviceRes.Body.Close()

	return (&v).Controller, nil

}
