package handlers

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/lucabrasi83/vulscano/logging"
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
		logging.VulscanoLog(
			"fatal",
			"Failed to initialize Docker environment settings: ",
			err.Error())
	}
	dockerStatus, err := cli.Ping(ctx)
	if err != nil {
		logging.VulscanoLog(
			"fatal",
			"Failed to connect to Docker daemon: ",
			err.Error())
	} else {
		logging.VulscanoLog(
			"info",
			"Detecting Docker Daemon...")
	}

	logging.VulscanoLog("info", "Docker API Version:", dockerStatus.APIVersion)

	// Check for VULSCANO_DOCKER_VOLUME_NAME Environment Variable to ensure we have a valid volume
	if os.Getenv("VULSCANO_DOCKER_VOLUME_NAME") == "" {
		logging.VulscanoLog(
			"fatal",
			"Environment Variable VULSCANO_DOCKER_VOLUME_NAME is not set!",
		)
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
		logging.VulscanoLog(
			"fatal",
			"Environment Variable DOCKER_HUB_USERNAME is not set!",
		)
	}
	if os.Getenv("DOCKER_HUB_PASSWORD") == "" {
		logging.VulscanoLog(
			"fatal",
			"Environment Variable DOCKER_HUB_PASSWORD is not set!",
		)
	}
	if os.Getenv("DOCKER_HUB_EMAIL") == "" {
		logging.VulscanoLog(
			"fatal",
			"Environment Variable DOCKER_HUB_EMAIL is not set!",
		)
	}

	// Set Authentication payload encoded to Base64 to login to Docker Hub
	dockerHubAuthBasePayload := fmt.Sprintf(`{
  								"username": "%v",
								"password": "%v",
 			 					"email": "%v",
 			 					"serveraddress": "https://index.docker.io/v1/"
								}`,
		os.Getenv("DOCKER_HUB_USERNAME"),
		os.Getenv("DOCKER_HUB_PASSWORD"),
		os.Getenv("DOCKER_HUB_EMAIL"))

	// Convert DOCKER_HUB Environment Vars credentials to Base64
	dockerHubAuthBase64 := base64.StdEncoding.EncodeToString([]byte(dockerHubAuthBasePayload))

	// Check if the Joval Scan Docker exists in local Docker host registry. If not download the image
	// using VULSCANO_DOCKER_JOVAL_IMAGE environment variable
	// TODO: Add type filter in ImageListOptions to only look for jovalscan image
	dockerImageList, err := cli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		logging.VulscanoLog(
			"fatal",
			"Error while trying to list Docker images in local registry: ",
			err.Error())
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
	// If no tatacomm/jovalscan image found in local Docker registry we're downloading it at startup
	if !imageFound {
		logging.VulscanoLog(
			"warning",
			"tatacomm/jovalscan Docker image not found in local Docker image registry.")

		logging.VulscanoLog(
			"info",
			"Downloading tatacomm/jovalscan Docker image: ", jovalDockerImage)
		now := time.Now()
		_, err := cli.ImagePull(ctx, jovalDockerImage, types.ImagePullOptions{
			All:          true,
			RegistryAuth: dockerHubAuthBase64,
		})

		if err != nil {
			logging.VulscanoLog(
				"fatal",
				"Failed to download tatacomm/jovalscan Docker image: ", jovalDockerImage, err.Error())
		}

		logging.VulscanoLog(
			"info",
			"Successful downloaded ", jovalDockerImage, " in ", time.Since(now))
	}

}

// LaunchJovalDocker handles the creation of Joval container to launch scan jobs
// It takes ScanResults pointer and JobID as parameters and returns an error in case
// of any issue reported during interaction with Docker daemon
func LaunchJovalDocker(jobID string) (err error) {

	// Container should run for maximum 10 minutes
	ctxContainerCancel, cancelContainerFunc := context.WithTimeout(ctx, 10*time.Minute)

	defer cancelContainerFunc()

	// We Create the container upon receiving a scan Job
	// Set Performance profile struct to allow different CPU/Memory allocations per container
	resp, errContainerCreate := cli.ContainerCreate(ctxContainerCancel, &container.Config{
		Image: os.Getenv("VULSCANO_DOCKER_JOVAL_IMAGE"),
		Tty:   true,
		Env:   []string{"INIFILE=" + filepath.FromSlash("./jobconfig/"+jobID+"/config.ini")},
	}, &container.HostConfig{
		AutoRemove: true,
		Resources: container.Resources{
			NanoCPUs: 2000000000,
			Memory:   1000000000,
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
	if errContainerStart := cli.ContainerStart(ctxContainerCancel, resp.ID, types.ContainerStartOptions{}); errContainerStart != nil {
		return errContainerStart
	}

	// Semaphore channel to signal when the container has exited
	sem := make(chan bool, 1)

	// Verify if the context channel is closed which means we have exceeded the timeout for a Joval scan job
	go func() {

		for {
			select {

			case <-ctxContainerCancel.Done():

				errStopContainer := cli.ContainerKill(context.TODO(), resp.ID, "SIGKILL")

				if errStopContainer != nil {
					logging.VulscanoLog("error",
						"failed to stop Joval scan container "+resp.ID+" for Job ID "+jobID,
					)
					err = errStopContainer
				}
				return

			case <-sem:
				return

			}
		}

	}()

	// The container will generate logs for each scan job.
	// We parse the logs for information such as device successful/failure scans, Mean Scan time,...
	outContainerLogs, errContainerLogs := cli.ContainerLogs(ctxContainerCancel, resp.ID, types.ContainerLogsOptions{
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

	exit, errCh := cli.ContainerWait(ctxContainerCancel, resp.ID)
	sem <- true

	if errCh != nil {
		return errCh
	}

	if exit != 0 {
		logging.VulscanoLog("error",
			"Scan container for Job ID "+jobID+" exited with code: ", exit)

		return fmt.Errorf("scan job ID %v failed with error code: %v", jobID, exit)
	}
	logging.VulscanoLog("info",
		"Scan container for Job ID "+jobID+" exited with code: ", exit)

	// Use bufferio Scanner to avoid loading entire  container logs content in memory
	containerLogs := bufio.NewScanner(outContainerLogs)

	// Loop through each line (this is the default behaviour and it matches how Joval renders logs)
	for containerLogs.Scan() {

		// Find error message from Joval that no scan was performed
		RegexpNoScan := regexp.MustCompile(`^WARNING: No scans$`)
		RegexpNoScanMatch := RegexpNoScan.MatchString(containerLogs.Text())
		if RegexpNoScanMatch {
			return fmt.Errorf("no scan performed for job ID %v . Check the job logs for details", jobID)
		}

	}
	return nil
}
