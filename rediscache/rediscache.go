package rediscache

import (
	"os"
	"time"

	"github.com/go-redis/redis"
	_ "github.com/lucabrasi83/vulscano/initializer" // Import for correct init functions order
	"github.com/lucabrasi83/vulscano/logging"
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

	if os.Getenv("VSCAN_REDIS_HOST") == "" {
		logging.VulscanoLog("fatal", "Environment Variable VSCAN_REDIS_HOST not set")
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
		logging.VulscanoLog("fatal",
			"Failed to connect to Redis instance ", err.Error())
	}

	logging.VulscanoLog("info", "Redis Cache Store connection pool successfully established")

	// Build Devices Inventory in cache during startup
	// err = CacheStore.BuildDeviceInventoryCache()

	//if err != nil {
	//	logging.VulscanoLog("error", err)
	//}

}

func newCacheStore(c *redis.Client) *vscanCache {
	return &vscanCache{
		cacheStoreClient: c,
	}
}

func (p *vscanCache) CloseCacheConn() {
	err := p.cacheStoreClient.Close()

	if err != nil {
		logging.VulscanoLog("error", "failed to close Redis Cache Store connection: ", err)
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
			logging.VulscanoLog("error", "failed to remove device with IP "+d+"from cacheStoreClient list")
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
		logging.VulscanoLog("error", "failed to check cache entry for device ", dev, err)

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
	err := p.cacheStoreClient.HMSet(dev, kv).Err()

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
