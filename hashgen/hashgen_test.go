package hashgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenHash(t *testing.T) {
	hash, err := GenHash()
	if err != nil {
		assert.Error(t, err, "Not able to generate Hash")

	}
	assert.Nil(t, err)
	assert.True(t, len(hash) > 0)
}
