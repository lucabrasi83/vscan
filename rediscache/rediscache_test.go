package rediscache

import (
	"testing"

	"github.com/go-redis/redis"
	"github.com/stretchr/testify/assert"
)

func helperRedisConn(t *testing.T) (*redis.Client, func() error) {

	t.Helper()

	return redisClient, redisClient.Close
}

func TestRedis(t *testing.T) {
	redisConn, redisTeardown := helperRedisConn(t)

	defer redisTeardown()

	ping, err := redisConn.Ping().Result()

	if err != nil {
		t.Fatalf("redis ping failed with error %v", err)
	}
	assert.Equal(t, "PONG", ping)
}
