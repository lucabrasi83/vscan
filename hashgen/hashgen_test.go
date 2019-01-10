package hashgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenHash(t *testing.T) {
	hash, err := GenHash()
	if err != nil {
		assert.True(t, hash == "")
		assert.Error(t, err, "not able to generate hash")

	}
	assert.Nil(t, err)
	assert.True(t, len(hash) > 0)
}
