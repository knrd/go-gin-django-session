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

// getSessionFromCookie attempts to retrieve and validate a Django session from cookie
// Returns the raw session and error (if any). Does not abort the request.
func getSessionFromCookie(c *gin.Context, config MiddlewareConfig) (*RawSession, error) {
	// Get session cookie
	sessionID, err := c.Cookie(config.Client.SessionCookieName())
	if err != nil || sessionID == "" {
		return nil, errors.New("no session cookie")
	}

	// Validate session existence and expiration WITHOUT decoding payload
	rawSession, err := config.Client.GetRawSession(c.Request.Context(), sessionID)
	if err != nil {
		return nil, err
	}

	return rawSession, nil
}

// setConfigDefaults sets default values for MiddlewareConfig
func setConfigDefaults(config *MiddlewareConfig) {
	if config.LoginRedirectURL == "" {
		config.LoginRedirectURL = "/account/login"
	}
	if config.SessionKey == "" {
		config.SessionKey = "django_session"
	}
}

// AuthMiddleware creates a Gin middleware that validates Django sessions
// It only checks if session exists and is not expired, WITHOUT decoding the payload
// Redirects to login page if session is invalid or missing.
func AuthMiddleware(config MiddlewareConfig) gin.HandlerFunc {
	setConfigDefaults(&config)

	return func(c *gin.Context) {
		rawSession, err := getSessionFromCookie(c, config)
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

// OptionalAuthMiddleware creates a Gin middleware that validates Django sessions
// but does NOT redirect when session is missing or invalid.
// If session exists and is valid, it will be stored in context.
// If session is missing or invalid, the request continues without setting session in context.
func OptionalAuthMiddleware(config MiddlewareConfig) gin.HandlerFunc {
	setConfigDefaults(&config)

	return func(c *gin.Context) {
		rawSession, err := getSessionFromCookie(c, config)
		if err == nil {
			// Store raw session in context only if valid
			c.Set(config.SessionKey, rawSession)
		}
		// Continue processing regardless of session validity
		c.Next()
	}
}
