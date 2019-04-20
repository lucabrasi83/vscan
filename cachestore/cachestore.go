package cachestore

import (
	"fmt"
	"os"
	"time"

	"github.com/go-redis/redis"
	"github.com/lucabrasi83/vulscano/logging"
)

var client *redis.Client

func init() {
	client = redis.NewClient(&redis.Options{
		Addr:         os.Getenv("VULSCANO_REDIS_HOST") + ":6379",
		Password:     "", // no password set
		DB:           0,  // use default DB,
		PoolSize:     20,
		MinIdleConns: 5,
	})

	pong, err := client.Ping().Result()
	fmt.Println(pong, err)

	err = client.HMSet("TEST-CPE", map[string]interface{}{
		"hostname":   "TEST-CPE.tatacommunications.com",
		"ip-address": "10.1.1.1",
		"os-type":    "IOS-XE",
		"os-version": "16.3.4",
	}).Err()

	if err != nil {
		logging.VulscanoLog("fatal", "cannot set redis key ", err)
	} else {
		err = client.Expire("TEST-CPE", 30*time.Second).Err()

		if err != nil {
			logging.VulscanoLog("fatal", "cannot set redis key ", err)
		}

	}
}
