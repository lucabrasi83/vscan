package postgresdb

import (
	"testing"
	"time"
)

func TestCiscoOpenVulnAPIDateConversion(t *testing.T) {
	date := "2020-05-06T16:00:00"
	layout := "2006-01-02T15:04:05"
	timeStamps, err := time.Parse(layout, date)

	if err != nil {
		t.Errorf("Test Failed with input error %v / Output %v", err, timeStamps)
	}

}
