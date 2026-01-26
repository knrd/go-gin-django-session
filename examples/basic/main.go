package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	djsession "github.com/knrd/go-gin-django-session"
)

func main() {
	// Load configuration from environment variables
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "django")
	dbPassword := getEnv("DB_PASSWORD", "secret")
	dbName := getEnv("DB_NAME", "djangodb")
	djangoSecretKey := getEnv("DJANGO_SECRET_KEY", "")

	if djangoSecretKey == "" {
		log.Fatal("DJANGO_SECRET_KEY environment variable is required")
	}

	// Connect to Django's PostgreSQL database
	connStr := "postgres://" + dbUser + ":" + dbPassword + "@" + dbHost + ":" + dbPort + "/" + dbName + "?sslmode=disable"

	db, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create Django session client
	client, err := djsession.NewClient(djsession.ClientConfig{
		DB:                db,
		SecretKey:         djangoSecretKey,
		SessionCookieName: "sessionid",
		MaxAge:            24 * time.Hour, // Optional: validate session age
	})
	if err != nil {
		log.Fatalf("Failed to create session client: %v", err)
	}
	log.Println("✓ Django session client initialized")

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Public routes (no authentication required)
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome! This is a public endpoint.",
			"endpoints": gin.H{
				"public":    "/",
				"protected": "/api/dashboard",
				"user":      "/api/user",
			},
		})
	})

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// Protected routes - require Django session authentication
	protected := r.Group("/api")
	protected.Use(djsession.AuthMiddleware(djsession.MiddlewareConfig{
		Client:     client,
		SessionKey: "django_session",
		OnError: func(c *gin.Context, err error) {
			log.Printf("Authentication error: %v", err)
			c.JSON(401, gin.H{
				"error":  "Authentication required",
				"detail": err.Error(),
			})
			c.Abort()
		},
	}))

	// Dashboard endpoint - demonstrates basic session usage
	protected.GET("/dashboard", func(c *gin.Context) {
		// Get raw session from context (set by middleware)
		rawSession := c.MustGet("django_session").(*djsession.RawSession)

		// Decode user ID from session (only when needed)
		userID, err := client.DecodeSessionUserID(rawSession.SessionData)
		if err != nil {
			log.Printf("Failed to decode session: %v", err)
			c.JSON(500, gin.H{"error": "Failed to decode session data"})
			return
		}

		c.JSON(200, gin.H{
			"message":    "Welcome to your dashboard!",
			"user_id":    userID,
			"session_id": rawSession.SessionKey,
			"expires_at": rawSession.ExpireDate,
		})
	})

	// User info endpoint - demonstrates session usage with user lookup
	protected.GET("/user", func(c *gin.Context) {
		rawSession := c.MustGet("django_session").(*djsession.RawSession)

		userID, err := client.DecodeSessionUserID(rawSession.SessionData)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to decode session"})
			return
		}

		// Here you could fetch user details from database
		// For demonstration, we just return the user ID
		c.JSON(200, gin.H{
			"user_id": userID,
			"session": gin.H{
				"session_key": rawSession.SessionKey,
				"expires_at":  rawSession.ExpireDate,
			},
		})
	})

	// Profile update endpoint - demonstrates write operations
	protected.POST("/profile", func(c *gin.Context) {
		rawSession := c.MustGet("django_session").(*djsession.RawSession)

		userID, err := client.DecodeSessionUserID(rawSession.SessionData)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to decode session"})
			return
		}

		var input struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		}

		if err := c.BindJSON(&input); err != nil {
			c.JSON(400, gin.H{"error": "Invalid input"})
			return
		}

		// Here you would update user profile in database
		log.Printf("User %s updating profile: name=%s, email=%s", userID, input.Name, input.Email)

		c.JSON(200, gin.H{
			"message": "Profile updated successfully",
			"user_id": userID,
		})
	})

	// Start server
	port := getEnv("PORT", "8080")
	log.Printf("🚀 Server starting on port %s", port)
	log.Printf("📝 Public endpoint: http://localhost:%s/", port)
	log.Printf("🔒 Protected endpoint: http://localhost:%s/api/dashboard", port)

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// getEnv returns the value of an environment variable or a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
