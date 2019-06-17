package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidEmail(t *testing.T) {
	emails :=
		[]struct {
			name  string
			email string
		}{
			{
				"Valid Email", "sebastien.pouplin@tatacommunications.com",
			},
			{
				"Valid Email", "seb123@gmail.com",
			},
			{
				"Invalid Email", ".@test.@#c",
			},
			{
				"Too long Email domain",
				"user@my_super_supra_very_long_email_address_that_no_one_can_ever_remember.co",
			},
		}

	for _, e := range emails {
		t.Run(e.name, func(t *testing.T) {

			if e.name == "Valid Email" {
				assert.Truef(t, validateEmail(e.email), "expected email %v validation to be true but got false", e)
			} else {
				assert.Falsef(t, validateEmail(e.email), "expected email %v validation to be false but got true", e)
			}
		})
	}
}
