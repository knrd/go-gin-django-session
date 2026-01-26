# Basic Example

This example demonstrates how to use `go-gin-django-session` to authenticate users against Django sessions.

## Prerequisites

1. Django application with database sessions enabled
2. PostgreSQL database with Django sessions
3. Go 1.21 or higher

## Setup

1. Install dependencies:

```bash
go mod init myapp
go get github.com/knrd/go-gin-django-session@v1.0.1
go get github.com/gin-gonic/gin
go get github.com/lib/pq
```

2. Set environment variables:

```bash
export DJANGO_SECRET_KEY="your-django-secret-key-here"
export DB_HOST="localhost"
export DB_PORT="5432"
export DB_USER="django"
export DB_PASSWORD="your-password"
export DB_NAME="djangodb"
export PORT="8080"
```

3. Run the example:

```bash
go run main.go
```

## Testing

### 1. Test public endpoint (no authentication):

```bash
curl http://localhost:8080/
```

### 2. Test protected endpoint (requires Django session):

First, log in to your Django application in a browser and get the session cookie.

Then use it with curl:

```bash
curl -b "sessionid=your-session-id-here" http://localhost:8080/api/dashboard
```

### 3. Test with invalid session:

```bash
curl -b "sessionid=invalid-session" http://localhost:8080/api/dashboard
```

Expected response: `401 Unauthorized`

## Endpoints

- `GET /` - Public endpoint, no authentication required
- `GET /health` - Health check endpoint
- `GET /api/dashboard` - Protected endpoint, returns user info
- `GET /api/user` - Protected endpoint, returns detailed user info
- `POST /api/profile` - Protected endpoint, updates user profile

## Notes

- The example uses environment variables for configuration
- Database connection pooling is configured for production use
- Custom error handler returns JSON responses
- Session validation is fast (no payload decoding in middleware)
- User ID is decoded only when needed in route handlers
