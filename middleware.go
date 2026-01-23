package django_session

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// MiddlewareConfig configures the authentication middleware
type MiddlewareConfig struct {
	Client           *Client
	LoginRedirectURL string                          // URL to redirect when auth fails (default: "/account/login")
	SessionKey       string                          // Context key for storing session (default: "django_session")
	OnError          func(c *gin.Context, err error) // Optional: custom error handler
}

// AuthMiddleware creates a Gin middleware that validates Django sessions
// It only checks if session exists and is not expired, WITHOUT decoding the payload
func AuthMiddleware(config MiddlewareConfig) gin.HandlerFunc {
	// Set defaults
	if config.LoginRedirectURL == "" {
		config.LoginRedirectURL = "/account/login"
	}
	if config.SessionKey == "" {
		config.SessionKey = "django_session"
	}

	return func(c *gin.Context) {
		// Get session cookie
		sessionID, err := c.Cookie(config.Client.SessionCookieName())
		if err != nil || sessionID == "" {
			if config.OnError != nil {
				config.OnError(c, errors.New("no session cookie"))
			} else {
				c.Redirect(http.StatusFound, config.LoginRedirectURL)
			}
			c.Abort()
			return
		}

		// Validate session existence and expiration WITHOUT decoding payload
		rawSession, err := config.Client.GetRawSession(c.Request.Context(), sessionID)
		if err != nil {
			if config.OnError != nil {
				config.OnError(c, err)
			} else {
				c.Redirect(http.StatusFound, config.LoginRedirectURL)
			}
			c.Abort()
			return
		}

		// Store raw session in context (payload NOT decoded yet)
		c.Set(config.SessionKey, rawSession)
		c.Next()
	}
}
