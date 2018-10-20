package hashgen

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenHash(t *testing.T) {
	hash, err := GenHash()
	assert.Nil(t, err)
	assert.True(t, len(hash) > 0)
}
