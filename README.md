# go-gin-django-session

A Go library for integrating Django session authentication with Gin web applications. This library allows your Go/Gin backend to authenticate users against Django sessions stored in PostgreSQL.

> **Note:** This code was developed with the assistance of Claude AI.

## Features

- ✅ **Tested with Django 4.2 - 6.0** - Should work with all modern Django versions
- ✅ **Django Session Validation** - Validate Django sessions in Go applications
- ✅ **Session Signature Verification** - Cryptographic verification using Django's signing algorithm
- ✅ **Fast Session Lookup** - Optimized for high-performance with lazy decoding
- ✅ **Gin Middleware** - Ready-to-use authentication middleware for Gin framework
- ✅ **User ID Extraction** - Extract authenticated user ID from session data
- ✅ **Configurable** - Support for custom session cookie names, max age, and logging

## Requirements

- **Go** 1.21 or higher
- **Django** backend with database sessions
- **PostgreSQL** database (or any database compatible with `database/sql`)
- **Gin** web framework v1.9.1+

## Installation

```bash
go get github.com/knrd/go-gin-django-session@v0.1.0
```

## Quick Start

### 1. Basic Setup

```go
package main

import (
    "database/sql"
    "log"
    
    "github.com/gin-gonic/gin"
    _ "github.com/lib/pq"
    djsession "github.com/knrd/go-gin-django-session"
)

func main() {
    // Connect to Django's PostgreSQL database
    db, err := sql.Open("postgres", 
        "host=localhost port=5432 user=django password=secret dbname=djangodb sslmode=disable")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Create Django session client
    client, err := djsession.NewClient(djsession.ClientConfig{
        DB:                db,
        SecretKey:         "your-django-secret-key",
        SessionCookieName: "sessionid", // Django default
    })
    if err != nil {
        log.Fatal(err)
    }

    // Setup Gin router
    r := gin.Default()

    // Protected routes with Django session authentication
    protected := r.Group("/api")
    protected.Use(djsession.AuthMiddleware(djsession.MiddlewareConfig{
        Client:           client,
        LoginRedirectURL: "/account/login",
    }))
    
    protected.GET("/dashboard", func(c *gin.Context) {
        // Get raw session from context
        rawSession := c.MustGet("django_session").(*djsession.RawSession)
        
        // Decode user ID only when needed
        userID, err := client.DecodeSessionUserID(rawSession.SessionData)
        if err != nil {
            c.JSON(500, gin.H{"error": "Failed to decode session"})
            return
        }
        
        c.JSON(200, gin.H{
            "message": "Welcome!",
            "user_id": userID,
        })
    })

    r.Run(":8080")
}
```

### 2. With Custom Configuration

```go
client, err := djsession.NewClient(djsession.ClientConfig{
    DB:                db,
    SecretKey:         os.Getenv("DJANGO_SECRET_KEY"),
    SessionCookieName: "sessionid",
    MaxAge:            24 * time.Hour, // Optional: validate session age
})
```

### 3. Custom Error Handling

```go
authMiddleware := djsession.AuthMiddleware(djsession.MiddlewareConfig{
    Client: client,
    OnError: func(c *gin.Context, err error) {
        c.JSON(401, gin.H{
            "error": "Authentication failed",
            "detail": err.Error(),
        })
        c.Abort()
    },
})
```

## API Reference

### Client

#### `NewClient(config ClientConfig) (*Client, error)`

Creates a new Django session client.

**Parameters:**
- `DB` (*sql.DB) - Database connection (required)
- `SecretKey` (string) - Django SECRET_KEY (required)
- `SessionCookieName` (string) - Session cookie name (default: "sessionid")
- `MaxAge` (time.Duration) - Maximum session age for validation (optional)

#### `GetRawSession(ctx context.Context, sessionKey string) (*RawSession, error)`

Retrieves and validates a session without decoding the payload. Fast operation for middleware.

**Returns:**
- `RawSession` with SessionKey, SessionData, and ExpireDate
- Errors: `ErrSessionNotFound`, `ErrSessionExpired`

#### `DecodeSessionUserID(sessionData string) (string, error)`

Decodes session payload and extracts the authenticated user ID.

**Returns:**
- User ID as string
- Errors: `ErrInvalidSignature`, or parsing errors

### Middleware

#### `AuthMiddleware(config MiddlewareConfig) gin.HandlerFunc`

Gin middleware for Django session authentication.

**Parameters:**
- `Client` (*Client) - Django session client (required)
- `LoginRedirectURL` (string) - Redirect URL on auth failure (default: "/account/login")
- `SessionKey` (string) - Context key for storing session (default: "django_session")
- `OnError` (func) - Custom error handler (optional)

**Behavior:**
- Validates session exists and is not expired
- Stores `RawSession` in Gin context (payload not decoded)
- Redirects or calls OnError on authentication failure

## Error Types

```go
var (
    ErrSessionNotFound  = errors.New("session not found")
    ErrSessionExpired   = errors.New("session expired")
    ErrInvalidSignature = errors.New("invalid session signature")
    ErrUserNotFound     = errors.New("user not found")
)
```

## Performance Optimization

The library uses a **two-phase approach** for optimal performance:

1. **Fast Path (Middleware)**: Only validates session existence and expiration
2. **Lazy Decoding**: Decode session payload only when user ID is needed

This avoids expensive cryptographic operations on every request.

## Django Configuration

Ensure your Django project uses database sessions:

```python
# settings.py
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'sessionid'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True  # For HTTPS
SESSION_COOKIE_SAMESITE = 'Lax'
```

## Testing

Run tests with:

```bash
go test -v ./...
```

## Examples

See the [`examples/`](examples/) directory for more usage examples:
- [`examples/basic/`](examples/basic/) - Basic authentication setup
- More examples coming soon!

## Security Considerations

- ⚠️ **Never expose SECRET_KEY** - Use environment variables
- ⚠️ **Use HTTPS in production** - Set `SESSION_COOKIE_SECURE = True` in Django
- ⚠️ **Validate session age** - Consider setting `MaxAge` in ClientConfig
- ⚠️ **Database connection pooling** - Configure `sql.DB` with appropriate pool settings

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Support

For issues, questions, or suggestions, please open an issue on GitHub.

## Version

Current version: **v0.1.0**

---

**Developed with assistance from Claude AI** 🤖
