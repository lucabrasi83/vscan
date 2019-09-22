package handlers

import (
	"time"

	"github.com/lucabrasi83/vulscano/inventorymgr"
	"github.com/lucabrasi83/vulscano/postgresdb"
)

// SchedulerBatchJobs will execute batch jobs at the specifier ticker interval
func SchedulerBatchJobs(tick *time.Ticker) {
	for ; true; <-tick.C {

		// Sync Inventory with VSCAN Cache
		go inventorymgr.BuildDevicesInventory()

		// Sync Cisco openVuln API with local vulnerabilities DB
		go func() {
			err := postgresdb.DBInstance.InsertAllCiscoAdvisories()
			if err != nil {
				return
			}
		}()

		// Fetch Suggested SW from Cisco and sync device AMC status
		go func() {
			_, err := GetAnutaDeviceSuggestedSW()
			if err != nil {
				return
			}

			err = FetchCiscoAMCStatus()
			if err != nil {
				return
			}
		}()

	}
}
