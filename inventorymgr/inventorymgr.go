// Package inventorymgr contains functions to interact with different device inventories supported by VSCAN
package inventorymgr

import "github.com/lucabrasi83/vulscano/logging"

// BuildDeviceInventoryCache is going to create a Hash Map Key for each device in the integrated inventories
func BuildDevicesInventory() {

	err := buildAnutaInventoryCache()

	if err != nil {
		logging.VulscanoLog("failed to build cache for Anuta NCX devices inventory", err)
	}
}
