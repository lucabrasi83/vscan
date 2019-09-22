package handlers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	agentpb "github.com/lucabrasi83/vscan/api/proto"
	"github.com/lucabrasi83/vscan/datadiros"
	"github.com/lucabrasi83/vscan/logging"
	"github.com/lucabrasi83/vscan/openvulnapi"
	"github.com/lucabrasi83/vscan/postgresdb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
)

var conn *grpc.ClientConn

var vscanAgentPort = "50051"

const (

	// singleDevScanTimeout represents the default 300 seconds scan timeout for a single device scan
	singleDevScanTimeout = 300

	// bulkDevScanTimeout represents the default 900 seconds scan timeout for a bulk scan
	bulkDevScanTimeout = 900
)

func agentConnection() (agentpb.VscanAgentServiceClient, error) {

	if os.Getenv("VSCAN_AGENT_HOST") == "" {
		return nil, fmt.Errorf("no agent specified in VSCAN_AGENT_HOST environment variable")
	}

	if os.Getenv("VSCAN_AGENT_PORT") != "" {
		vscanAgentPort = os.Getenv("VSCAN_AGENT_PORT")
	}

	tlsCredentials, errTLSCredentials := clientCertLoad()

	if errTLSCredentials != nil {
		return nil, errTLSCredentials
	}

	var err error

	conn, err = grpc.Dial(os.Getenv("VSCAN_AGENT_HOST")+":"+vscanAgentPort, grpc.WithTransportCredentials(tlsCredentials))

	if err != nil {
		logging.VSCANLog("fatal", "unable to dial VSCAN Agent GRPC server: ", err)
	}

	c := agentpb.NewVscanAgentServiceClient(conn)

	return c, nil

}

func sendAgentScanRequest(jobID string, dev []map[string]string, jovalSource string, sshGW *UserSSHGateway,
	creds *UserDeviceCredentials, sr *ScanResults, bsr *BulkScanResults) error {

	cc, err := agentConnection()

	if err != nil {

		return fmt.Errorf("error while establishing connection to VSCAN agent %v", err)
	}

	// Closing GRPC client connection at the end of scan job
	defer conn.Close()

	var devices []*agentpb.Device

	// Set the Scan Timeout to be sent to the agent depending on number of devices scanned
	var scanTimeout int

	if len(dev) > 1 {
		scanTimeout = bulkDevScanTimeout
	} else {
		scanTimeout = singleDevScanTimeout
	}

	for _, d := range dev {
		devices = append(devices, &agentpb.Device{DeviceName: d["hostname"], IpAddress: d["ip"]})
	}

	req := &agentpb.ScanRequest{
		JobId:         jobID,
		OvalSourceUrl: jovalSource,
		Devices:       devices,
		UserDeviceCredentials: &agentpb.UserDeviceCredentials{
			CredentialsName: creds.CredentialsName,
			Username:        creds.Username,
			Password:        creds.Password,
		},
		SshGateway: &agentpb.SSHGateway{
			GatewayName:       sshGW.GatewayName,
			GatewayIp:         sshGW.GatewayIP.String(),
			GatewayPrivateKey: sshGW.GatewayPrivateKey,
			GatewayPassword:   sshGW.GatewayPassword,
			GatewayUsername:   sshGW.GatewayUsername,
		},
		ScanTimeoutSeconds: int64(scanTimeout),
	}

	// Setting timeout context for scan requests
	ctxTimeout, cancel := context.WithTimeout(context.Background(), time.Duration(scanTimeout)*time.Second)

	defer cancel()

	// Send Scan Request
	stream, err := cc.BuildScanConfig(ctxTimeout, req, grpc.UseCompressor(gzip.Name))

	if err != nil {
		respErr, ok := status.FromError(err)

		if ok {

			if respErr.Code() == codes.DeadlineExceeded {
				return fmt.Errorf("VSCAN agent is unable to complete the request within the %v seconds timeout",
					scanTimeout)
			}

			return fmt.Errorf("VSCAN agent is unable to proceed with scan request for job ID %v with error: %v",
				jobID, respErr.Message())

		}

		return fmt.Errorf("VSCAN agent is unable to proceed with scan request for job ID %v with error: %v",
			jobID, err)

	}

	// Start receiving Scan Reports stream
	for {
		resStream, err := stream.Recv()

		if err == io.EOF {
			break
		}

		if err != nil {

			respErr, ok := status.FromError(err)

			if ok {

				return fmt.Errorf("error while receiving response stream from VSCAN agent for job ID %v : %v"+
					"GRPC error code %v", jobID, respErr.Message(), respErr.Code())

			}

			return fmt.Errorf("error while receiving response stream from VSCAN agent for job ID %v : %v",
				jobID, err)
		}

		logging.VSCANLog("info",
			fmt.Sprintf("Agent %v - Scan Job ID %v - received file stream for device %v\n",
				resStream.GetVscanAgentName(), jobID, resStream.GetDeviceName()))

		// If more than one device requested for scan, handle it as a Bulk Scan
		if len(devices) > 0 && bsr != nil {

			// Add Agent Name in scan results
			bsr.ScanJobExecutingAgent = resStream.VscanAgentName

			err = parseGRPCBulkScanReport(bsr, jobID, resStream.GetScanResultsJson())

			if err != nil {
				logging.VSCANLog(

					"error",
					"unable to parse scan results for device ", resStream.GetDeviceName(), " during Job ID ", jobID,
				)
			}

		} else {

			// Add Agent Name in scan results
			sr.ScanJobExecutingAgent = resStream.VscanAgentName

			err = parseGRPCScanReport(sr, jobID, resStream.GetScanResultsJson())

			if err != nil {
				return err
			}

		}

	}

	return nil

}

func parseGRPCScanReport(res *ScanResults, jobID string, scanFileRes []byte) error {

	const jovalReportFoundTag = "fail"

	var scanReport ScanReportFile

	err := json.Unmarshal(scanFileRes, &scanReport)

	if err != nil {
		return fmt.Errorf("error while parsing JSON report file for Job ID %v: %v", jobID, err)
	}
	// vulnCount determines the number of vulnerabilities found in the report
	var vulnCount int

	// vulnTotal determines the number of total vulnerabilities scanned
	vulnTotal := len(scanReport.RuleResults)

	// Verify that Joval JSON report rule_results array contains elements
	if vulnTotal > 0 {

		// duplicateSAMap tracks duplicates SA found in Joval Scan Report
		duplicateSAMap := map[string]bool{}

		// vulnMetaSlice is a slice of Cisco openVuln API vulnerabilities metadata
		vulnMetaSlice := make([]openvulnapi.VulnMetadata, 0, 30)

		// Declare WaitGroup to send requests to openVuln API in parallel
		var wg sync.WaitGroup

		// We set a rate limit to throttle Goroutines querying DB for Vulnerabilities metadata.
		rateLimit := time.NewTicker(20 * time.Millisecond)

		defer rateLimit.Stop()

		// Declare Mutex to prevent Race condition on vulnMetaSlice slice
		var mu sync.RWMutex

		// Loop to search for found vulnerabilities in the scan report and fetch metadata for each
		// vulnerability in a goroutine
		for _, ruleResult := range scanReport.RuleResults {

			// Count number of found vulnerabilities in report to determine Wait Group length
			// Update duplicateSAMap to find duplicated Cisco SA in Joval Report
			if ruleResult.RuleResult == jovalReportFoundTag &&
				!duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] {
				duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] = true

				// Update count of vulnerabilities found
				vulnCount++

				// Increment WaitGroup by 1 before launching goroutine
				wg.Add(1)

				go func(r ScanReportFileResult) {
					defer wg.Done()
					<-rateLimit.C

					vulnMeta := postgresdb.DBInstance.FetchCiscoSAMeta(r.RuleIdentifier[0].ResultCiscoSA)

					// Exclusive access to vulnMetaSlice to prevent race condition
					mu.Lock()
					vulnMetaSlice = append(vulnMetaSlice, *vulnMeta)
					mu.Unlock()

				}(ruleResult)

			}

		}
		wg.Wait()
		// Start mapping Report File into ScanResults struct
		res.VulnerabilitiesFoundDetails = vulnMetaSlice
		res.TotalVulnerabilitiesFound = vulnCount
		res.TotalVulnerabilitiesScanned = vulnTotal

		deviceScanStartTime, _ := time.Parse(time.RFC3339, scanReport.ScanStartTime)
		deviceScanEndTime, _ := time.Parse(time.RFC3339, scanReport.ScanEndTime)
		res.ScanDeviceMeanTime = int(deviceScanEndTime.Sub(deviceScanStartTime).Seconds() * 1000)

	} else {
		return fmt.Errorf("agent %v - scan job ID %v - unable to scan the device requested. "+
			"Make sure the parameters provided are correct and verify network connectivity",
			res.ScanJobExecutingAgent, jobID)
	}
	return nil

}

func parseGRPCBulkScanReport(res *BulkScanResults, jobID string, scanFileRes []byte) error {

	const jovalReportFoundTag = "fail"

	var scanReport ScanReportFile

	err := json.Unmarshal(scanFileRes, &scanReport)

	if err != nil {
		return fmt.Errorf("error while parsing JSON report file for Job ID %v: %v", jobID, err)
	}
	// vulnCount determines the number of vulnerabilities found in the report
	var vulnCount int

	// vulnTotal determines the number of total vulnerabilities scanned
	vulnTotal := len(scanReport.RuleResults)

	// Verify that Joval JSON report rule_results array contains elements
	if vulnTotal > 0 {

		// duplicateSAMap tracks duplicates SA found in Joval Scan Report
		duplicateSAMap := map[string]bool{}

		// vulnMetaSlice is a slice of Cisco openVuln API vulnerabilities metadata
		vulnMetaSlice := make([]openvulnapi.VulnMetadata, 0, 30)

		// Declare WaitGroup to send requests to openVuln API in parallel
		var wg sync.WaitGroup

		// We set a rate limit to throttle Goroutines querying DB for Vulnerabilities metadata.
		rateLimit := time.NewTicker(20 * time.Millisecond)

		defer rateLimit.Stop()

		// Declare Mutex to prevent Race condition on vulnMetaSlice slice
		var mu sync.RWMutex

		// Loop to search for found vulnerabilities in the scan report and fetch metadata for each
		// vulnerability in a goroutine
		for _, ruleResult := range scanReport.RuleResults {

			// Count number of found vulnerabilities in report to determine Wait Group length
			// Update duplicateSAMap to find duplicated Cisco SA in Joval Report
			if ruleResult.RuleResult == jovalReportFoundTag &&
				!duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] {
				duplicateSAMap[ruleResult.RuleIdentifier[0].ResultCiscoSA] = true

				// Update count of vulnerabilities found
				vulnCount++

				// Increment WaitGroup by 1 before launching goroutine
				wg.Add(1)

				go func(r ScanReportFileResult) {
					defer wg.Done()
					<-rateLimit.C

					vulnMeta := postgresdb.DBInstance.FetchCiscoSAMeta(r.RuleIdentifier[0].ResultCiscoSA)

					// Exclusive access to vulnMetaSlice to prevent race condition
					mu.Lock()
					vulnMetaSlice = append(vulnMetaSlice, *vulnMeta)
					mu.Unlock()

				}(ruleResult)

			}

		}
		wg.Wait()

		// Format in type Time the Device Scan Mean Time from Joval JSON Report
		deviceScanStartTime, _ := time.Parse(time.RFC3339, scanReport.ScanStartTime)
		deviceScanEndTime, _ := time.Parse(time.RFC3339, scanReport.ScanEndTime)

		vulnFound := BulkScanVulnFound{
			DeviceName:                  scanReport.DeviceName,
			ScanDeviceMeanTime:          int(deviceScanEndTime.Sub(deviceScanStartTime).Seconds() * 1000),
			VulnerabilitiesFoundDetails: vulnMetaSlice,
			TotalVulnerabilitiesScanned: vulnTotal,
			TotalVulnerabilitiesFound:   vulnCount,
		}
		// Start mapping Report File into BulkScanResults struct
		res.VulnerabilitiesFound = append(res.VulnerabilitiesFound, vulnFound)
	} else {
		// Devices with empty rule_results JSON array were not successfully scanned
		// Append to the DevicesScannedFailure slice
		res.DevicesScannedFailure = append(res.DevicesScannedFailure, scanReport.DeviceName)
	}

	return nil

}

func clientCertLoad() (credentials.TransportCredentials, error) {

	// Load the certificates from disk

	certificate, errCert := tls.LoadX509KeyPair(
		filepath.FromSlash(datadiros.GetDataDir()+"/certs/vscan.pem"),
		filepath.FromSlash(datadiros.GetDataDir()+"/certs/vscan.key"))

	if errCert != nil {
		return nil, fmt.Errorf("error while loading VSCAN agent client certificate: %v", errCert)
	}

	// Create a certificate pool from the certificate authority
	certPool := x509.NewCertPool()

	ca, errCert := ioutil.ReadFile(datadiros.GetDataDir() + "/certs/TCL-ENT-CA.pem")
	if errCert != nil {
		return nil, fmt.Errorf("error while loading VSCAN agent root Certificate Authority %v", errCert)
	}

	// Append the client certificates from the CA
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, fmt.Errorf("failed to append Root CA %v certs", ca)
	}

	return credentials.NewTLS(&tls.Config{
		ServerName:   os.Getenv("VSCAN_AGENT_HOST"),
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
	}), nil

}
