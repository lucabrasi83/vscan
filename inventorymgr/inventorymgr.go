// Package inventorymgr contains functions to interact with different device inventories supported by VSCAN
package inventorymgr

import "github.com/lucabrasi83/vscan/logging"

// BuildDeviceInventoryCache is going to create a Hash Map Key for each device in the integrated inventories
func BuildDevicesInventory() {

	err := buildAnutaInventoryCache()

	if err != nil {
		logging.VSCANLog("Failed to build cache for Anuta NCX devices inventory", err)
		return
	}
	logging.VSCANLog("info",
		"Synchronization task of Devices Inventory backend with VSCAN cache has completed")

}
