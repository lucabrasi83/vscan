package hashgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenHash(t *testing.T) {
	hash, err := GenHash()
	if assert.Nil(t, err) {

		assert.Nil(t, err)
		assert.True(t, len(hash) > 0)

	} else {
		assert.Error(t, err, "expected error got nil")
	}
}

func TestErrorNewHashIDMinLength(t *testing.T) {

	hd := newhdData()

	hd.Alphabet = "A"
	hd.Salt = "Vul$can0 RoCk$"
	hd.MinLength = 30

	_, err := newHashID(hd)

	assert.NotNil(t, err, "expected error got nil")

}

func TestErrorNewHashIDSpaceAlphabet(t *testing.T) {

	hd := newhdData()

	hd.Alphabet = "A "

	_, err := newHashID(hd)

	assert.NotNil(t, err, "expected error got nil")
}

func TestErrorHashIDEncode(t *testing.T) {
	hd := newhdData()
	hd.Salt = "Vul$can0 RoCk$"
	hd.MinLength = 30

	h, _ := newHashID(hd)

	_, err := hashIDEncode(h, []int{})

	assert.NotNil(t, err, "expected error got nil")
}
