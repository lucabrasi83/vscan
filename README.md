# VSCAN


[![Build Status](https://travis-ci.com/lucabrasi83/vscan.svg?token=Rjzx1thyrVmqNDLuUZ1P&branch=master)](https://travis-ci.com/lucabrasi83/vscan)
[![codecov](https://codecov.io/gh/lucabrasi83/vscan/branch/master/graph/badge.svg?token=Y5byK7OnSd)](https://codecov.io/gh/lucabrasi83/vscan)
![Docker Cloud Automated build](https://img.shields.io/docker/cloud/automated/tatacomm/vscan-controller?style=flat-square)
![Docker Cloud Build Status](https://img.shields.io/docker/cloud/build/tatacomm/vscan-controller?style=flat-square)
![MicroBadger Size (tag)](https://img.shields.io/microbadger/image-size/tatacomm/vscan-controller/latest?style=flat-square)
[![GolangCI](https://golangci.com/badges/github.com/lucabrasi83/vscan-controller.svg)](https://golangci.com/r/github.com/lucabrasi83/vscan)
[![Job Status](https://docstand.rocro.com/badges/github.com/lucabrasi83/vscan/status?token=xwzHrjcWq5_ajaRHXPPzhY1agb3ZF1Sx-12hCBRUJAc)](https://docstand.rocro.com/jobs/github.com/lucabrasi83/vscan/latest?completed=true)
[![godoc](https://docstand.rocro.com/badges/github.com/lucabrasi83/vscan/documentation/godoc?token=xwzHrjcWq5_ajaRHXPPzhY1agb3ZF1Sx-12hCBRUJAc&branch=master)](https://docstand.rocro.com/docs/github.com/lucabrasi83/vscan/branch/master/godoc/github.com/lucabrasi83/vscan/)
#   

<p align="center">
<img align="center" src ="https://github.com/lucabrasi83/vscan/blob/master/logo/vulscano_logo.png?raw=true" />
</p>

#   

VSCAN is a TATA Communications developed application that handles Vulnerability Scanning and Reporting for Cisco IOS/IOS
-XE devices.

It allows you to request on-demand Vulnerability Assessment on a particular device through a simple API.

The VA scan job is launched in real-time and will provide the results using latest published OVAL definitions.

You can find more details about the OVAL standard for Vulnerability Assessment here: [https://oval.mitre.org/](https://oval.mitre.org/)

## Contents

- [Software Version Requirements](#software-version-requirements)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)



## Software Version Requirements

Container is the core of Vulscano infrastructure and therefore following software is required:

| Software       | Version        | 
| -------------- |:--------------:| 
| Docker CE      | `>=17.04.0-ce` | 
| Docker-Compose |    `1.22.0`    |


> **Note:** Linux distro is highly recommended to run Docker. Make sure you have a working outbound Internet connectivity on the host


## Getting Started

1. Clone the repo: 
```sh
$ git clone https://github.com/lucabrasi83/vscan.git
```
2. Navigate to the repo:
```sh
$ cd vulscano
```

3. Create Docker volume:
```sh
$ docker volume create --opt device=$(pwd) --opt o=bind vulscanovol
```

4. Set Environment Variables:
 Refer to the section [Environment Variables](#environment-variables) to properly define those

5. Start application:
 ```sh
 $ docker-compose up
 ```

6. If you see the message below you're all good  :relaxed:
 ```diff
 + Vulscano is now READY
 ```

7. Launch a Vulnerability scan with any HTTP client such as Postman or cURL. You can specify the router hostname, ip and os_type (IOS-XE or IOS) in the request body.

    > **NOTE:** Recommend to use  'jq' to prettify JSON output with cURL [https://stedolan.github.io/jq/download/](https://stedolan.github.io/jq/download/)
    

    - Negotiate HTTP version:
    
    ```sh
    $ curl -s -k https://localhost:8443/api/v1/ondemandscan \ 
           -H "Content-Type: application/json" \
           -X POST -d '{"hostname": "CSR1000V_RTR1", "ip":"192.168.1.70", "os_type":"IOS-XE"}' | jq
    ```

    - Force HTTP/2 (if your cURL client was compiled with nghttp2 library. You can verify with `curl --version` ):

    ```sh
    $ curl -s --http2-prior-knowledge \
      -k https://localhost:8443/api/v1/ondemandscan \
      -H "Content-Type: application/json" \
      -X POST -d '{"hostname": "CSR1000V_RTR1", "ip":"192.168.1.70", "os_type":"IOS-XE"}' | jq
    ```

    - 200 OK Response body:

```javascript
  {
    "results": {
       "scanJobID": "V9Vx75w8eOkBWRXug8nWDmY31yazre",
       "scanJobStartTime": "Tue Oct 30 04:04:49 UTC 2018",
       "scanJobEndTime": "  Tue Oct 30 04:04:59 UTC 2018",
       "scanJobDeviceMeanTime": "6038ms",
       "totalVulnerabilitiesFound": 5,
       "vulnerabilitiesFoundDetails": [
        {
            "advisoryId": "cisco-sa-20180926-pnp-memleak",
            "advisoryTitle": "Cisco IOS and IOS XE Software Plug and Play Agent Memory Leak Vulnerability",
            "firstPublished": "2018-09-26T16:00:00-0500",
            "bugIDs": [
            "CSCvi30136"
            ],
            "cves": [
            "CVE-2018-15377"
            ],
            "sir": "Medium",
            "cvssBaseScore": "6.8",
            "publicationUrl": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-pnp-memleak"
        },
        {
            "advisoryId": "cisco-sa-20180926-iosxe-cmdinj",
            "advisoryTitle": "Cisco IOS XE Software Command Injection Vulnerabilities",
            "firstPublished": "2018-09-26T16:00:00-0500",
            "bugIDs": [
            "CSCvh02919",
            "CSCvh54202"
            ],
            "cves": [
            "CVE-2018-0477",
            "CVE-2018-0481"
            ],
            "sir": "High",
            "cvssBaseScore": "6.7",
            "publicationUrl": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-iosxe-cmdinj"
        },
        {
            "advisoryId": "cisco-sa-20180926-iosxe-cmdinj",
            "advisoryTitle": "Cisco IOS XE Software Command Injection Vulnerabilities",
            "firstPublished": "2018-09-26T16:00:00-0500",
            "bugIDs": [
            "CSCvh02919",
            "CSCvh54202"
            ],
            "cves": [
            "CVE-2018-0477",
            "CVE-2018-0481"
            ],
            "sir": "High",
            "cvssBaseScore": "6.7",
            "publicationUrl": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-iosxe-cmdinj"
        },
        {
            "advisoryId": "cisco-sa-20180926-macsec",
            "advisoryTitle": "Cisco IOS XE Software MACsec MKA Using EAP-TLS Authentication Bypass Vulnerability",
            "firstPublished": "2018-09-26T16:00:00-0500",
            "bugIDs": [
            "CSCvh09411"
            ],
            "cves": [
            "CVE-2018-15372"
            ],
            "sir": "Medium",
            "cvssBaseScore": "6.5",
            "publicationUrl": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-macsec"
        },
        {
            "advisoryId": "cisco-sa-20180926-digsig",
            "advisoryTitle": "Cisco IOS XE Software Digital Signature Verification Bypass Vulnerability",
            "firstPublished": "2018-09-26T16:00:00-0500",
            "bugIDs": [
            "CSCvh15737"
            ],
            "cves": [
            "CVE-2018-15374"
            ],
            "sir": "Medium",
            "cvssBaseScore": "6.7",
            "publicationUrl": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-digsig"
        }
      ]
    }
  }
```


## Environment variables

You must set environment variables in the .env file from this repo. It will be read by Docker-Compose to load them.

Environment variables the application is consuming at startup are defined as below table:

| Name                                    | Description                                 | Required  |
|:----------------------------------------|:--------------------------------------------|:---------:|
| `VULSCANO_HTTPS_PORT`                   |  HTTPS port your host is going to listen to | `YES`     |
| `VULSCANO_DOCKER_JOVAL_IMAGE`           |  Docker Joval Scan image.                   | `YES`     |
| `VULSCANO_OPENVULN_CLIENT_ID`           |  Cisco openVuln API client ID               | `YES`     |
| `VULSCANO_OPENVULN_CLIENT_SECRET`       |  Cisco openVuln Client Secret               | `YES`     |
| `VULSCANO_CISCO_ROUTER_USERNAME`        |  Cisco IOS/IOS-XE Router username           | `YES`     |
| `VULSCANO_CISCO_ROUTER_PASSWORD`        |  Cisco IOS/IOS-XE Router password           | `YES`     |
| `VULSCANO_CISCO_ROUTER_ENABLE_PASSWORD` |  Cisco IOS/IOS-XE Router enable password    | `NO`      |
| `VULSCANO_DOCKER_VOLUME_NAME`           |  Docker Bind Volume for persistency         | `YES`     |
| `DOCKER_HUB_USERNAME`                   |  Docker Hub account username                | `YES`     |
| `DOCKER_HUB_PASSWORD`                   |  Docker Hub account password                | `YES`     |
| `DOCKER_HUB_EMAIL`                      |  Docker Hub account email                   | `YES`     |


> **Note:** As part of beta release, credentials are set in environment variables which is not considered safe.
Production release will be using [Hashicorp Vault](https://www.vaultproject.io/) in order to store secrets
and [Let's Encrypt](https://letsencrypt.org/) for automated TLS certificate issuance.
