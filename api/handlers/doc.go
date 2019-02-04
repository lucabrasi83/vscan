// Package handlers contains the main business logic for API endpoints.
// It is composed of various files as described below:
//
// File inibuilder.go handles creation of config.ini file for Joval Scan jobs.
// Based on scan job inputs in REST API request body, it will dynamically generate ini sections for:
//	. Target Devices Hostname and IP Address
//	. Device Credentials
//	. Log folder unique per scan job ID
//	. Reports folder unique per scan job ID
//
// File dockerlib.go handles interaction with Docker daemon to launch Joval Scan containers.
// It communicates via /var/run/docker.sock file by default and allows compute resource controls per scan job.
//
// File handlers.go contains the API endpoints binding functions.
//
// File types.go contains the various struct types used by the API handlers functions.
//
// File scanner.go contains the business logic to execute single device vulnerability assessments.
//
// File bulkscanner.go contains the business logic to execute vulnerability assessments in bulk (multiple devices in
// a single scan job).
package handlers
