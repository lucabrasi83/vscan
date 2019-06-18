package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/appleboy/gin-jwt/v2"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vulscano/logging"
)

var (
	fgHiGreen   = color.New(color.FgHiGreen)
	fgHiCyan    = color.New(color.FgHiCyan)
	fgHiRed     = color.New(color.FgHiRed)
	bgHiBlue    = color.New(color.BgHiBlue, color.FgHiWhite)
	fgOrange    = color.New(color.FgRed, color.FgYellow)
	bgHiMagenta = color.New(color.BgHiMagenta, color.FgHiWhite)
	bgHiOrange  = color.New(color.BgRed, color.BgYellow, color.FgHiWhite)
	fgHiYellow  = color.New(color.FgHiYellow)
	fgHiMagenta = color.New(color.FgHiMagenta)
	bgHiRed     = color.New(color.BgHiRed, color.FgHiWhite)
	bgHiYellow  = color.New(color.BgHiYellow, color.FgBlack)
)

// RequestsLogger middleware handles logging of HTTP Requests with pretty format using Vulscano logging package
// Request are logged in both incoming and sent directions
func RequestsLogger() gin.HandlerFunc {
	return func(c *gin.Context) {

		now := time.Now()

		// Process next handlers before logging
		c.Next()

		// Default User ID for API Handler not requiring authorization
		userID := "anonymous@vulscano.com"

		// Extract User ID from JWT Claim
		jwtClaim := jwt.ExtractClaims(c)

		if userJWT, ok := jwtClaim["email"].(string); ok {
			userID = userJWT
		}

		logResMessage := fmt.Sprintf(
			"Request Received: %s | User: %s | Client IP: %v | Response Code: %s | Reponse Time: %s | URL: %s",
			colorForMethod(c.Request.Method).Sprintf("%6s", c.Request.Method),
			fgHiMagenta.Sprintf("%-30s", userID),
			fgHiCyan.Sprintf("%-15v", c.ClientIP()),
			colorForStatus(c.Writer.Status()).Sprintf("%3d", c.Writer.Status()),
			fgHiYellow.Sprintf("%-13v", time.Since(now).String()),
			bgHiBlue.Sprint(c.Request.URL),
		)
		logging.VulscanoLog("info",
			logResMessage,
		)

	}

}

func colorForStatus(code int) *color.Color {
	switch {
	case code >= http.StatusOK && code < http.StatusMultipleChoices:
		return fgHiGreen
	case code >= http.StatusMultipleChoices && code < http.StatusBadRequest:
		return fgOrange
	case code >= http.StatusBadRequest && code < http.StatusInternalServerError:
		return fgHiRed
	default:
		return fgHiRed
	}
}

func colorForMethod(method string) *color.Color {
	switch method {
	case "GET":
		return bgHiBlue
	case "POST":
		return bgHiMagenta
	case "PUT":
		return bgHiOrange
	case "DELETE":
		return bgHiRed
	case "PATCH":
		return bgHiYellow
	default:
		return bgHiBlue
	}
}
