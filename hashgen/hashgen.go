package hashgen

import (
	"math/rand"
	"os"
	"time"

	"github.com/speps/go-hashids"
)

// GenHash function will generate a unique Hash using the current time in Unix epoch format as the seed
func GenHash() (string, error) {

	hdData := newhdData()

	h, err := newHashID(hdData)

	if err != nil {
		return "", err
	}

	UnixTime := time.Now().UnixNano()
	IntUnixTime := int(UnixTime)

	e, err := hashIDEncode(h, []int{IntUnixTime, IntUnixTime + rand.Intn(1000)})

	if err != nil {
		return "", err
	}

	return e, nil
}

func newhdData() *hashids.HashIDData {
	hd := hashids.NewData()
	hd.Salt = os.Getenv("VSCAN_SECRET_KEY")
	hd.MinLength = 30

	return hd
}

func newHashID(data *hashids.HashIDData) (*hashids.HashID, error) {
	h, err := hashids.NewWithData(data)

	if err != nil {
		return nil, err
	}

	return h, nil
}

func hashIDEncode(h *hashids.HashID, nano []int) (string, error) {

	e, err := h.Encode(nano)

	if err != nil {
		return "", err
	}

	return e, nil
}
