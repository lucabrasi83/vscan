package inventorymgr

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lucabrasi83/vscan/logging"
	"github.com/lucabrasi83/vscan/rediscache"
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

type AnutaAPIAllDevices struct {
	Devices []AnutaAPIDeviceDetails `json:"device"`
}

type AnutaAPIAllDevicesParent struct {
	Controller AnutaAPIAllDevices `json:"controller:devices"`
}

const (
	anutaDeviceFilters = "?fields=id;mgmt-ip-address;status;os-version;" +
		"iosxeversion:iosxe-version/version;ostype-string;device-type;serial-number;name"

	anutaAllDevicesFilters = "?fields=device/id;device/mgmt-ip-address;device/status;device/os-version;" +
		"device/iosxeversion:iosxe-version/version;device/ostype-string;device/device-type;device/serial-number" +
		";device/name"

	shortHTTPReqTimeout = 10 * time.Second
	longHTTPReqTimeout  = 10 * time.Minute
)

var (
	anutaNCXHost  = os.Getenv("ANUTA_NCX_HOST")
	anutaBaseAuth = os.Getenv("ANUTA_NCX_BASE64_AUTH")
)

func GetAnutaDevice(dev string) (*AnutaAPIDeviceDetails, error) {

	// Check if Device Exists in Cache Store First
	// If true, then return the device object from cache
	if devCacheExists, err := rediscache.CacheStore.CheckCacheEntryExists(dev); devCacheExists && err == nil {

		devCacheEntry := rediscache.CacheStore.HGetAllDeviceDetails(dev)

		return &AnutaAPIDeviceDetails{
			DeviceName:    dev,
			MgmtIPAddress: devCacheEntry["mgmtIPAddress"],
			Status:        devCacheEntry["status"],
			OSType:        devCacheEntry["osType"],
			OSVersion:     devCacheEntry["osVersion"],
			SerialNumber:  devCacheEntry["serialNumber"],
			CiscoModel:    devCacheEntry["model"],
			Hostname:      devCacheEntry["hostname"],
			RealIOSXEVersion: AnutaIOSXEVersionChildContainer{
				IOSXEVersionChildContainer: devCacheEntry["realIOSXEVersion"],
			},
		}, nil
	}

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

	ctx, cancel := context.WithTimeout(anutaDeviceReq.Context(), shortHTTPReqTimeout)
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

	// Insert Device into Cache for next lookup
	err = rediscache.CacheStore.HashMapSetDevicesInventory(v.Controller.DeviceName, map[string]interface{}{
		"mgmtIPAddress":    v.Controller.MgmtIPAddress,
		"status":           v.Controller.Status,
		"osType":           v.Controller.OSType,
		"osVersion":        v.Controller.OSVersion,
		"model":            v.Controller.CiscoModel,
		"serialNumber":     v.Controller.SerialNumber,
		"hostname":         v.Controller.Hostname,
		"realIOSXEVersion": v.Controller.RealIOSXEVersion.IOSXEVersionChildContainer,
	})

	if err != nil {
		logging.VSCANLog("warning",
			"Failed to insert device %v into inventory cache with error %v", v.Controller.DeviceName, err)
	}

	return (&v).Controller, nil

}

func getAllAnutaInventoryDevices() ([]AnutaAPIDeviceDetails, error) {

	// Construct API Call URL to query device details
	url := strings.Join([]string{
		"https://",
		anutaNCXHost,
		"/restconf/data/controller:devices.json",
		anutaAllDevicesFilters,
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
		return nil, fmt.Errorf("cannot fetch inventory details from Anuta: %v", err)
	}

	anutaDeviceReq.Header.Add("Content-Type", "application/json")
	anutaDeviceReq.Header.Add("Authorization", "Basic "+anutaBaseAuth)

	ctx, cancel := context.WithTimeout(anutaDeviceReq.Context(), longHTTPReqTimeout)
	defer cancel()

	anutaDeviceReq = anutaDeviceReq.WithContext(ctx)

	anutaDeviceRes, err := anutaHTTPClient.Do(anutaDeviceReq)

	if err != nil {
		return nil, fmt.Errorf("error while contacting Anuta NCX API: %v", err)
	}
	if anutaDeviceRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"cannot get inventory details from Anuta NCX API. HTTP Error Code %v",
			anutaDeviceRes.Status)
	}

	var v AnutaAPIAllDevicesParent
	if err := json.NewDecoder(anutaDeviceRes.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("error while serializing struct into JSON body: %v", err)
	}

	defer anutaDeviceRes.Body.Close()

	return (&v).Controller.Devices, nil

}

func buildAnutaInventoryCache() error {
	if anutaNCXHost != "" {
		devList, err := getAllAnutaInventoryDevices()

		if err != nil {
			return err
		}

		var wg sync.WaitGroup

		wg.Add(len(devList))

		for _, d := range devList {
			go func(dev AnutaAPIDeviceDetails) {
				err := rediscache.CacheStore.HashMapSetDevicesInventory(dev.DeviceName, map[string]interface{}{
					"mgmtIPAddress":    dev.MgmtIPAddress,
					"status":           dev.Status,
					"osType":           dev.OSType,
					"osVersion":        dev.OSVersion,
					"model":            dev.CiscoModel,
					"serialNumber":     dev.SerialNumber,
					"hostname":         dev.Hostname,
					"realIOSXEVersion": dev.RealIOSXEVersion.IOSXEVersionChildContainer,
				})

				if err != nil {
					logging.VSCANLog("warning",
						"Failed to insert device %v into inventory cache with error %v", dev.DeviceName, err)
				}

				wg.Done()

			}(d)
		}

		wg.Wait()

	}
	return nil
}
