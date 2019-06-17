package rediscache

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testCacheStore *vscanCache

func TestMain(m *testing.M) {

	// Assign Cache Store instance for all Tests
	testCacheStore = newCacheStore(redisClient)

	// Purge All keys before starting the tests
	testCacheStore.cacheStoreClient.FlushAll()

	flag.Parse()
	exitCode := m.Run()

	// Close Redis connection after tests are done
	testCacheStore.CloseCacheConn()

	os.Exit(exitCode)

}

func TestRedisConn(t *testing.T) {

	ping, err := testCacheStore.cacheStoreClient.Ping().Result()

	if err != nil {
		t.Fatalf("redis ping failed with error %v", err)
	}
	assert.Equal(t, "PONG", ping)
}

func TestOngoingScannedDevicesIP(t *testing.T) {

	tableTestDevices := []string{"CPE1", "CPE2", "CPE3", "CPE4"}

	t.Run("Purge ongoing scanned devices list", func(t *testing.T) {
		err := testCacheStore.PurgeScannedDevices()
		assert.Nil(t, err, "expected err to be nil but got %v", err)
	})

	t.Run("Test LPush devices", func(t *testing.T) {
		err := testCacheStore.LPushScannedDevicesIP(tableTestDevices...)
		assert.Nilf(t, err, "expected err to be nil but got %v", err)
	})

	t.Run("Test LRange devices", func(t *testing.T) {
		dev, err := testCacheStore.LRangeScannedDevices()
		assert.Nilf(t, err, "expected err to be nil but got %v", err)

		assert.ElementsMatchf(t, dev, tableTestDevices, "expected %v to have same elements as %v", dev, tableTestDevices)
	})

	t.Run("Test LRem devices", func(t *testing.T) {
		testCacheStore.LRemScannedDevicesIP(tableTestDevices...)
		dev, err := testCacheStore.LRangeScannedDevices()
		assert.Nilf(t, err, "expected err to be nil but got %v", err)

		assert.Equalf(t, 0, len(dev), "expected dev slice length to be %v but got %v", 0, len(dev))
	})

}

func TestDeviceInventoryCache(t *testing.T) {

	testDeviceKey := "TEST-CPE"

	testDeviceDetails := map[string]interface{}{
		"mgmtIPAddress":    "10.1.1.1",
		"status":           "ONLINE",
		"osType":           "IOS-XE",
		"osVersion":        "16.7.1",
		"model":            "ISR 4221",
		"serialNumber":     "ABCDFFEEZZ",
		"hostname":         "TEST-CPE.vscan.com",
		"realIOSXEVersion": "16.07.01",
	}

	t.Run("Check device does not exist in cache", func(t *testing.T) {
		exists, err := testCacheStore.CheckCacheEntryExists(testDeviceKey)

		assert.Nilf(t, err, "expected err to be nil but got %v", err)
		assert.False(t, exists, "expected CPE exists to be false but got true")
	})

	t.Run("Insert device into cache", func(t *testing.T) {
		err := testCacheStore.HashMapSetDevicesInventory(testDeviceKey, testDeviceDetails)
		assert.Nilf(t, err, "expected err to be nil but got %v", err)
	})

	t.Run("Check device exists in cache", func(t *testing.T) {
		exists, err := testCacheStore.CheckCacheEntryExists(testDeviceKey)

		assert.Nilf(t, err, "expected err to be nil but got %v", err)
		assert.True(t, exists, "expected CPE exists to be true but got false")
	})

	t.Run("Get device from cache", func(t *testing.T) {
		dev := testCacheStore.HGetAllDeviceDetails(testDeviceKey)

		assert.Contains(t, dev, "mgmtIPAddress", "expected dev map to contain mgmtIPAddress key but got nil")
		assert.Equalf(t, "10.1.1.1", dev["mgmtIPAddress"], "expected mgmtIPAddress key value to be %q but got %q",
			"10.1.1.1", dev["mgmtIPAddress"])
	})

}

func TestCloseCacheStoreConn(t *testing.T) {

	testCacheStore.CloseCacheConn()
	ping, err := testCacheStore.cacheStoreClient.Ping().Result()

	t.Run("Check ping value is empty", func(t *testing.T) {

		assert.Emptyf(t, ping, "expected ping to be empty but got %v", ping)
	})

	t.Run("Check error is returned when trying to close connection", func(t *testing.T) {

		assert.NotNilf(t, err, "expected err not to be nil but got %v", err)
	})
}
