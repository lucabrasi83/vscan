package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	agentpb "github.com/lucabrasi83/vulscano/api/proto"
	"github.com/lucabrasi83/vulscano/logging"
	"github.com/lucabrasi83/vulscano/openvulnapi"
	"github.com/lucabrasi83/vulscano/postgresdb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
)

var conn *grpc.ClientConn

var vscanAgentPort = "50051"

func agentConnection() (agentpb.VscanAgentServiceClient, error) {

	if os.Getenv("VSCAN_AGENT_HOST") == "" {
		return nil, fmt.Errorf("no agent specified in VSCAN_AGENT_HOST environment variable")
	}

	if os.Getenv("VSCAN_AGENT_PORT") != "" {
		vscanAgentPort = os.Getenv("VSCAN_AGENT_PORT")
	}

	var err error

	conn, err = grpc.Dial(os.Getenv("VSCAN_AGENT_HOST")+":"+vscanAgentPort, grpc.WithInsecure())

	if err != nil {
		logging.VulscanoLog("fatal", "unable to dial VSCAN Agent GRPC server: ", err)
	}

	// defer conn.Close()

	c := agentpb.NewVscanAgentServiceClient(conn)

	return c, nil

}

func sendAgentScanRequest(jobID string, dev []map[string]string, jovalSource string, sshGW *UserSSHGateway,
	creds *UserDeviceCredentials, sr *ScanResults, bsr *BulkScanResults) error {

	cc, err := agentConnection()

	if err != nil {

		return fmt.Errorf("error while establishing connection to VSCAN Agent %v\n", err)
	}

	// Closing GRPC client connection at the end of scan job
	defer conn.Close()

	var devices []*agentpb.Device

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
	}

	// Send Scan Request
	stream, err := cc.BuildScanConfig(context.Background(), req, grpc.UseCompressor(gzip.Name))

	if err != nil {
		respErr, ok := status.FromError(err)

		if ok {

			return fmt.Errorf("VSCAN Agent is unable to proceed with scan request for job ID %v with error: %v\n",
				jobID, respErr.Message())

		} else {

			return fmt.Errorf("VSCAN Agent is unable to proceed with scan request for job ID %v with error: %v\n",
				jobID, err)
		}

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

				return fmt.Errorf("error while receiving response stream from VSCAN agent for job ID %v : %v\n",
					jobID, respErr.Message())

			}

			return fmt.Errorf("error while receiving response stream from VSCAN agent for job ID %v : %v\n",
				jobID, err)
		}

		logging.VulscanoLog("info",
			fmt.Sprintf("Scan Job ID %v - received file stream from VSCAN Agent %v for device %v\n", jobID,
				resStream.GetVscanAgentName(), resStream.GetDeviceName()))

		// If more than one device requested for scan, handle it as a Bulk Scan
		if len(devices) > 0 && bsr != nil {

			err = parseGRPCBulkScanReport(bsr, jobID, resStream.GetScanResultsJson())

			if err != nil {
				logging.VulscanoLog(

					"error",
					"unable to parse scan results for device ", resStream.GetDeviceName(), " during Job ID ", jobID,
				)
			}

		} else {
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
		return fmt.Errorf("Scan job ID %v - unable to scan the device requested. "+
			"Make sure the parameters provided are correct and verify network connectivity\n", jobID)
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
