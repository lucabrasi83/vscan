package hashgen

import (
	"github.com/speps/go-hashids"
	"math/rand"
	"time"
)

func GenHash() (string, error) {

	UnixTime := time.Now().UnixNano()
	IntUnixTime := int(UnixTime)

	hd := hashids.NewData()
	hd.Salt = "Vul$can0 RoCk$"
	hd.MinLength = 30
	h, err := hashids.NewWithData(hd)
	if err != nil {
		return "", err
	}
	e, err := h.Encode([]int{IntUnixTime, IntUnixTime + rand.Intn(1000)})

	if err != nil {
		return "", err
	}

	return e, nil
}
