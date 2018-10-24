// Package dockerlib handles interaction with Docker daemon to launch Joval Scan containers.
// It communicates via /var/run/docker.sock file by default and allows compute resource controls per scan job
package handlers

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var cli *client.Client
var ctx context.Context

// init function in Dockerlib package performs various checks on the Docker environment before starting
// the Vulscano application
func init() {

	ctx = context.Background()
	var err error
	cli, err = client.NewEnvClient()
	if err != nil {
		panic("Failed to initialize Docker environment settings")
	}
	dockerStatus, err := cli.Ping(ctx)
	if err != nil {
		panic("Failed to connect to Docker daemon")
	}
	log.Println("Docker API Version:", dockerStatus.APIVersion)

	// Check for VULSCANO_DOCKER_VOLUME_NAME Environment Variable to ensure we have a valid volume
	if os.Getenv("VULSCANO_DOCKER_VOLUME_NAME") == "" {
		log.Fatalln("Environment Variable  VULSCANO_DOCKER_VOLUME_NAME is not set!")
	}

	// If VULSCANO_DOCKER_JOVAL_IMAGE environment variable not found set it to tatacomm/jovalscan:latest
	var jovalDockerImage string
	if os.Getenv("VULSCANO_DOCKER_JOVAL_IMAGE") == "" {
		jovalDockerImage = "tatacomm/jovalscan:latest"
	} else {
		jovalDockerImage = os.Getenv("VULSCANO_DOCKER_JOVAL_IMAGE")
	}

	// Check for Docker Hub Login, Password, Email environment details
	// Since Joval Scan Docker image is private, Docker Hub credentials are required to download the image
	// The registry authentication payload is encoded as base64
	if os.Getenv("DOCKER_HUB_USERNAME") == "" {
		log.Fatalln("Environment Variable DOCKER_HUB_USERNAME is not set!")
	}
	if os.Getenv("DOCKER_HUB_PASSWORD") == "" {
		log.Fatalln("Environment Variable DOCKER_HUB_PASSWORD is not set!")
	}
	if os.Getenv("DOCKER_HUB_EMAIL") == "" {
		log.Fatalln("Environment Variable DOCKER_HUB_PASSWORD is not set!")
	}

	dockerHubAuthBasePayload := fmt.Sprintf(`{
  								"username": "%v",
								"password": "%v",
 			 					"email": "%v",
 			 					"serveraddress": "https://index.docker.io/v1/"
								}`,
		os.Getenv("DOCKER_HUB_USERNAME"),
		os.Getenv("DOCKER_HUB_PASSWORD"),
		os.Getenv("DOCKER_HUB_EMAIL"))

	dockerHubAuthBase64 := base64.StdEncoding.EncodeToString([]byte(dockerHubAuthBasePayload))

	// Check if the Joval Scan Docker exists in local Docker host registry. If not download the image
	// using VULSCANO_DOCKER_JOVAL_IMAGE environment variable
	// TODO: Add type filter in ImageListOptions to only look for jovalscan image
	dockerImageList, err := cli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		panic(err)
	}
	var imageFound = false
	for _, imageTagList := range dockerImageList {
		for _, imageTag := range imageTagList.RepoTags {
			if imageTag == jovalDockerImage {
				imageFound = true
				break
			}
		}
	}
	if !imageFound {
		log.Println("tatacomm/jovalscan Docker image not found in local Docker image registry.")
		log.Println("Downloading Docker Joval image:", jovalDockerImage)
		now := time.Now()
		_, err := cli.ImagePull(ctx, jovalDockerImage, types.ImagePullOptions{
			All:          true,
			RegistryAuth: dockerHubAuthBase64,
		})

		if err != nil {
			log.Fatalln("Failed to download", jovalDockerImage, err.Error())
		}
		log.Println("Successful downloaded", jovalDockerImage, "in", time.Since(now))
		log.Println("Vulscano is now ready for some work!!!")
	}

}

// LaunchJovalDocker handles the creation of Joval container to launch scan jobs
// It takes ScanResults pointer and JobID as parameters and returns an error in case of any issue reported during
// interaction with Docker daemon
func LaunchJovalDocker(sr *ScanResults, jobID string) (err error) {

	// This is the default Docker image for jovalscan
	const imageName string = "tatacomm/jovalscan:0.2"

	// We Create the container upon receiving a scan Job
	// Set Performance profile struct to allow different CPU/Memory allocations per container
	resp, errContainerCreate := cli.ContainerCreate(ctx, &container.Config{
		Image: imageName,
		Tty:   true,
		Env:   []string{"INIFILE=" + filepath.FromSlash("./jobconfig/"+jobID+"/config.ini")},
	}, &container.HostConfig{
		AutoRemove: true,
		Resources: container.Resources{
			NanoCPUs: 2000000000,
			Memory:   2000000000,
		},
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeVolume,
				Source: os.Getenv("VULSCANO_DOCKER_VOLUME_NAME"),
				Target: "/opt/jovalscan",
			},
		},
	}, nil, "")

	if errContainerCreate != nil {
		return errContainerCreate
	}

	// Here we launch the container and get its SHA-1 ID returned by the Docker daemon
	if errContainerStart := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); errContainerStart != nil {
		return errContainerStart
	}

	// The container will generate logs for each scan job.
	// We parse the logs for information such as device successful/failure scans, Mean Scan time,...
	outContainerLogs, errContainerLogs := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{
		ShowStdout: true,
		Follow:     true})

	if errContainerLogs != nil {
		return errContainerLogs

	}
	defer func() {
		if errCloseLogs := outContainerLogs.Close(); errCloseLogs != nil {

			err = errCloseLogs
		}
	}()

	exit, errCh := cli.ContainerWait(ctx, resp.ID)
	fmt.Println("Scan container exited with code:", exit)
	if errCh != nil {
		return errCh
	}

	if exit != 0 {
		return fmt.Errorf("scan job ID %v failed with error code: %v", jobID, exit)
	}

	// Use bufferio Scanner to avoid loading entire  container logs content in memory
	containerLogs := bufio.NewScanner(outContainerLogs)

	// Loop through each line (this is the default behaviour and it matches how Joval renders logs)
	for containerLogs.Scan() {

		// Find the Device Scan Mean Time
		RegexpMeanTime := regexp.MustCompile(`Mean target scan duration: (.*)`)
		RegexpMeanTimeMatch := RegexpMeanTime.FindStringSubmatch(containerLogs.Text())
		if len(RegexpMeanTimeMatch) >= 2 {
			(*sr).ScanDeviceMeanTime = RegexpMeanTimeMatch[1]
		}

		// Find the Scan Job Start Time
		RegexpStartTime := regexp.MustCompile(`Scan start time: (.*)`)
		RegexpStartTimeMatch := RegexpStartTime.FindStringSubmatch(containerLogs.Text())
		if len(RegexpStartTimeMatch) >= 2 {
			(*sr).ScanJobStartTime = RegexpStartTimeMatch[1]
		}

		// Find the Scan Job End Time
		RegexpEndTime := regexp.MustCompile(`Scan end time: (.*)`)
		RegexpEndTimeMatch := RegexpEndTime.FindStringSubmatch(containerLogs.Text())
		if len(RegexpEndTimeMatch) >= 2 {
			(*sr).ScanJobEndTime = RegexpEndTimeMatch[1]
		}

	}

	return nil
}
