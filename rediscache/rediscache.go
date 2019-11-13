package rediscache

import (
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis"
	_ "github.com/lucabrasi83/vscan/initializer" // Import for correct init functions order
	"github.com/lucabrasi83/vscan/logging"
)

type vscanCache struct {
	cacheStoreClient *redis.Client
}

var redisClient *redis.Client
var CacheStore *vscanCache

const (
	ongoingScannedDevicesKey = "devices-being-scanned"
)

func init() {

	// Disable Init Function when running tests
	for _, arg := range os.Args {
		if strings.Contains(arg, "test") {
			return
		}
	}

	if os.Getenv("VSCAN_REDIS_HOST") == "" {
		logging.VSCANLog("fatal", "Environment Variable VSCAN_REDIS_HOST not set")
	}

	// Set Redis Client options
	redisClient = redis.NewClient(&redis.Options{
		Addr:         os.Getenv("VSCAN_REDIS_HOST") + ":6379",
		Password:     os.Getenv("VSCAN_REDIS_PASSWORD"),
		DB:           0, // use default DB,
		PoolSize:     20,
		MinIdleConns: 5,
	})

	// Instantiate cacheStoreClient Store object
	CacheStore = newCacheStore(redisClient)

	// Verify Redis is UP and Running
	_, err := CacheStore.cacheStoreClient.Ping().Result()
	if err != nil {
		logging.VSCANLog("fatal",
			"Failed to connect to Redis instance %v", err.Error())
	}

	logging.VSCANLog("info", "Redis Cache Store connection pool successfully established")

}

func newCacheStore(c *redis.Client) *vscanCache {
	return &vscanCache{
		cacheStoreClient: c,
	}
}

func (p *vscanCache) CloseCacheConn() {
	err := p.cacheStoreClient.Close()

	if err != nil {
		logging.VSCANLog("error", "failed to close Redis Cache Store connection %v", err)
	}
}
func (p *vscanCache) LPushScannedDevicesIP(dev ...string) error {
	err := p.cacheStoreClient.LPush(ongoingScannedDevicesKey, dev).Err()

	return err
}

func (p *vscanCache) LRemScannedDevicesIP(dev ...string) {

	for _, d := range dev {
		err := p.cacheStoreClient.LRem(ongoingScannedDevicesKey, 0, d).Err()

		if err != nil {
			logging.VSCANLog("error",
				"failed to remove device with IP %v from cacheStoreClient list with error %v", d, err)
		}
	}
}

func (p *vscanCache) LRangeScannedDevices() ([]string, error) {
	ret, err := p.cacheStoreClient.LRange(ongoingScannedDevicesKey, 0, -1).Result()

	return ret, err
}

func (p *vscanCache) PurgeScannedDevices() error {
	err := p.cacheStoreClient.Del(ongoingScannedDevicesKey).Err()

	return err
}

func (p *vscanCache) CheckCacheEntryExists(dev string) (bool, error) {
	entry, err := p.cacheStoreClient.HGetAll(dev).Result()

	if err != nil {
		logging.VSCANLog("error", "failed to check cache entry for device %v with error %v", dev, err)

		return false, err
	}

	// Check if Mgmt IP Address key value exists in Hash Map. If not, return false means the key does not exist
	if val, ok := entry["mgmtIPAddress"]; ok && val != "" {
		return true, nil
	}

	return false, nil
}

func (p *vscanCache) HGetAllDeviceDetails(dev string) map[string]string {
	d := p.cacheStoreClient.HGetAll(dev).Val()
	return d
}

func (p *vscanCache) HashMapSetDevicesInventory(dev string, kv map[string]interface{}) error {

	err := p.cacheStoreClient.HMSet(strings.ToUpper(dev), kv).Err()

	if err != nil {
		return err
	}

	// Set Device Key to expire after 24 hours
	err = p.cacheStoreClient.Expire(dev, 24*time.Hour).Err()

	if err != nil {
		return err
	}
	return nil
}

func (p *vscanCache) SetBatchJobsRunningKey(i int) error {

	err := p.cacheStoreClient.Set("batchjobsrunning", i, 1*time.Hour).Err()
	return err
}

func (p *vscanCache) GetBatchJobsRunningKey() (bool, error) {

	val, err := p.cacheStoreClient.Get("batchjobsrunning").Int()

	if err != redis.Nil && err != nil {
		return true, err
	}

	valToBool := func(v int) bool {
		return v == 1
	}

	return valToBool(val), nil
}

func (p *vscanCache) scanCacheDeviceKey(pattern string) ([]string, error) {

	searchRes := make([]string, 0)

	var initCursor uint64

	for {

		dev, cursor, err := p.cacheStoreClient.Scan(initCursor, strings.ToUpper(pattern), 100).Result()

		if err != nil {
			return nil, err
		}
		initCursor = cursor

		searchRes = append(searchRes, dev...)

		if cursor == 0 {
			return searchRes, nil
		}
	}

}

func (p *vscanCache) SearchCacheDevice(pattern string) ([]map[string]string, error) {
	searchRes, err := p.scanCacheDeviceKey(pattern)

	devCacheInventory := make([]map[string]string, 0, len(searchRes))

	if err != nil {
		return nil, err
	}

	for _, dev := range searchRes {
		devCacheOSType, err := p.cacheStoreClient.HGet(dev, "osType").Result()
		if err != nil {
			devCacheOSType = "UNKNOWN"
		}

		devCacheModel, err := p.cacheStoreClient.HGet(dev, "model").Result()
		if err != nil {
			devCacheModel = "Unknown"
		}

		devCacheInventory = append(devCacheInventory, map[string]string{
			"device": dev,
			"osType": devCacheOSType,
			"model":  devCacheModel})
	}

	return devCacheInventory, nil
}
