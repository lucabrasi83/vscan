// Package initializer provides some helper function during application startup to display local environment
// information such as hardware, OS versions, banner and build revisions
package initializer

import (
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/lucabrasi83/vscan/logging"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
)

var (
	Commit  string
	Version string
	BuiltAt string
	BuiltOn string
)

func init() {

	// Disable Init Function when running tests
	for _, arg := range os.Args {
		if strings.Contains(arg, "test") {
			return
		}
	}

	// Gin by default disables logging timestamps. Re-enabling it here
	log.SetFlags(log.LstdFlags)

	// Call bunch of functions in the same package to display some environment info
	printBanner()
	printReleaseDetails()
	printPlatformDetails()

}

// printBanner will print the Vulscano Banner at startup
func printBanner() {

	fmt.Printf("\n")
	banner, err := os.Open("banner.txt")
	if err != nil {
		logging.VSCANLog("error", "Not able to load banner: ", err.Error())
	}
	defer banner.Close()
	_, err = io.Copy(os.Stdout, banner)
	if err != nil {
		logging.VSCANLog("error", "Not able to load banner: ", err.Error())
	}
	fmt.Printf("\n\n")
}

// printReleaseDetails is called as part of init() function and display Vulscano release details such as
// Git Commit, Git tag, build date,...
func printReleaseDetails() {
	fmt.Println(logging.UnderlineText("VSCAN Controller Release:"), logging.InfoMessage(Version))
	fmt.Println(logging.UnderlineText("Github Commit:"), logging.InfoMessage(Commit))

	fmt.Println(logging.UnderlineText(
		"Compiled @"), logging.InfoMessage(BuiltAt),
		"on", logging.InfoMessage(BuiltOn))

	fmt.Printf("\n")
}

// printPlatformDetails is called as part of init() function and display local platform details such as
// CPU info, OS & kernel Version, disk usage on partition "/",...
func printPlatformDetails() {

	platform, err := host.Info()

	if err != nil {
		logging.VSCANLog("error", "Unable to fetch platform details:", err.Error())
	} else {
		fmt.Println(
			logging.UnderlineText("Hostname:"),
			logging.InfoMessage(platform.Hostname))
		fmt.Println(
			logging.UnderlineText("Operating System:"),
			logging.InfoMessage(platform.OS),
			logging.InfoMessage(platform.PlatformVersion))
		fmt.Println(logging.UnderlineText("Kernel Version:"), logging.InfoMessage(platform.KernelVersion))
	}

	cpuDetails, err := cpu.Info()
	if err != nil {
		logging.VSCANLog("error", "Unable to fetch CPU details:", err.Error())
	} else {
		fmt.Println(logging.UnderlineText("CPU Model:"), logging.InfoMessage(cpuDetails[0].ModelName))
		fmt.Println(logging.UnderlineText("CPU Core(s):"), logging.InfoMessage(runtime.NumCPU()))
		fmt.Println(logging.UnderlineText("OS Architecture:"), logging.InfoMessage(runtime.GOARCH))
	}

	diskUsage, err := disk.Usage("/")

	if err != nil {
		logging.VSCANLog("error", "Unable to fetch disk Usage details:", err.Error())
	} else {
		diskUsageRounded := strconv.Itoa(int(math.Round(diskUsage.UsedPercent)))

		fmt.Println(
			logging.UnderlineText("Disk Usage Percentage:"), logging.InfoMessage(diskUsageRounded, "%"))
	}

	memUsage, err := mem.VirtualMemory()

	if err != nil {
		logging.VSCANLog("error", "Unable to fetch Memory details:", err.Error())
	} else {
		memUsageRounded := strconv.Itoa(int(math.Round(memUsage.UsedPercent)))
		fmt.Println(
			logging.UnderlineText("Virtual Memory Usage:"), logging.InfoMessage(memUsageRounded, "%"))
	}

	fmt.Printf("\n")

}
