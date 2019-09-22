package handlers

import (
	"fmt"
	"sync"
	"time"

	"github.com/lucabrasi83/vscan/inventorymgr"
	"github.com/lucabrasi83/vscan/logging"
	"github.com/lucabrasi83/vscan/postgresdb"
	"github.com/lucabrasi83/vscan/rediscache"
)

// SchedulerBatchJobs will execute batch jobs at the specifier ticker interval
func SchedulerBatchJobs(tick *time.Ticker) {
	for ; true; <-tick.C {

		logging.VSCANLog("info", "Starting scheduled Batch Jobs execution...")

		var wg sync.WaitGroup

		// Don't run batch jobs if another VSCAN controller is currently executing them
		if checkBatchJobsRunning() {
			logging.VSCANLog(
				"info",
				"Skipping batch jobs execution as another VSCAN controller is currently executing")
			continue
		}

		// Set batchjobsrunning Key in Cache Store to notify other controllers that Batch Jobs are being executing
		err := setBatchJobsRunningKey(1)
		if err != nil {
			continue
		}

		// Sync Inventory with VSCAN Cache
		wg.Add(1)
		go func() {
			defer wg.Done()
			inventorymgr.BuildDevicesInventory()
		}()

		// Sync Cisco openVuln API with local vulnerabilities DB
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := postgresdb.DBInstance.InsertAllCiscoAdvisories()
			if err != nil {
				return
			}
		}()

		// Fetch Suggested SW from Cisco and sync device AMC status
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := GetAnutaDeviceSuggestedSW()
			if err != nil {
				return
			}

			err = FetchCiscoAMCStatus()
			if err != nil {
				return
			}
		}()

		wg.Wait()
		logging.VSCANLog("info", "Scheduled Batch Jobs execution has completed")

		// Set batchjobsrunning Key in Cache Store to notify other controllers that Batch Jobs have finished executing
		err = setBatchJobsRunningKey(0)
		if err != nil {
			continue
		}
	}
}

// checkBatchJobsRunning function will check on the Cache Store
// whether VSCAN controllers are currently running a batch job
func checkBatchJobsRunning() bool {

	val, err := rediscache.CacheStore.GetBatchJobsRunningKey()

	if err != nil {
		logging.VSCANLog("error",
			fmt.Sprintf("failed to retrieve batchjobsrunning key in Cache Store. error: %v", err))
		return true
	}

	return val
}

func setBatchJobsRunningKey(i int) error {

	err := rediscache.CacheStore.SetBatchJobsRunningKey(i)

	if err != nil {
		logging.VSCANLog("error",
			fmt.Sprintf("failed to set batchjobsrunning key in Cache Store. error: %v", err))
	}

	return err
}
