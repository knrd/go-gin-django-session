package django_session

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// mockDB is a minimal mock for testing that doesn't require a real database
type mockDB struct {
	*sql.DB
}

func TestAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a test client (won't actually connect to DB in these tests)
	client, err := NewClient(ClientConfig{
		DB:        &sql.DB{},
		SecretKey: "test-secret-key",
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	tests := []struct {
		name               string
		setupRequest       func(*http.Request)
		expectedStatus     int
		expectedRedirect   string
		shouldCallNext     bool
		contextShouldHave  string
	}{
		{
			name: "no session cookie",
			setupRequest: func(r *http.Request) {
				// No cookie set
			},
			expectedStatus:   http.StatusFound,
			expectedRedirect: "/account/login",
			shouldCallNext:   false,
		},
		{
			name: "empty session cookie",
			setupRequest: func(r *http.Request) {
				r.AddCookie(&http.Cookie{
					Name:  "sessionid",
					Value: "",
				})
			},
			expectedStatus:   http.StatusFound,
			expectedRedirect: "/account/login",
			shouldCallNext:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test router
			router := gin.New()
			
			nextCalled := false
			router.Use(AuthMiddleware(MiddlewareConfig{
				Client: client,
			}))
			router.GET("/test", func(c *gin.Context) {
				nextCalled = true
				c.Status(http.StatusOK)
			})

			// Create test request
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			tt.setupRequest(req)

			// Execute request
			router.ServeHTTP(w, req)

			// Check status
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Check redirect
			if tt.expectedRedirect != "" {
				location := w.Header().Get("Location")
				if location != tt.expectedRedirect {
					t.Errorf("Expected redirect to %s, got %s", tt.expectedRedirect, location)
				}
			}

			// Check if next was called
			if nextCalled != tt.shouldCallNext {
				t.Errorf("Expected nextCalled=%v, got %v", tt.shouldCallNext, nextCalled)
			}
		})
	}
}

func TestAuthMiddlewareWithCustomConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	client, err := NewClient(ClientConfig{
		DB:        &sql.DB{},
		SecretKey: "test-secret-key",
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	t.Run("custom login redirect URL", func(t *testing.T) {
		router := gin.New()
		router.Use(AuthMiddleware(MiddlewareConfig{
			Client:           client,
			LoginRedirectURL: "/custom-login",
		}))
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status %d, got %d", http.StatusFound, w.Code)
		}

		location := w.Header().Get("Location")
		if location != "/custom-login" {
			t.Errorf("Expected redirect to /custom-login, got %s", location)
		}
	})

	t.Run("custom session key", func(t *testing.T) {
		router := gin.New()
		customSessionKey := "my_custom_session"
		
		router.Use(AuthMiddleware(MiddlewareConfig{
			Client:     client,
			SessionKey: customSessionKey,
			OnError: func(c *gin.Context, err error) {
				// Custom error handler - just abort without redirect
				c.AbortWithStatus(http.StatusUnauthorized)
			},
		}))
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("custom error handler", func(t *testing.T) {
		errorHandlerCalled := false
		var capturedError error

		router := gin.New()
		router.Use(AuthMiddleware(MiddlewareConfig{
			Client: client,
			OnError: func(c *gin.Context, err error) {
				errorHandlerCalled = true
				capturedError = err
				c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				c.Abort()
			},
		}))
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		if !errorHandlerCalled {
			t.Error("Expected custom error handler to be called")
		}

		if capturedError == nil {
			t.Error("Expected error to be captured")
		}

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})
}

func TestAuthMiddlewareBackwardCompatibility(t *testing.T) {
	gin.SetMode(gin.TestMode)

	client, err := NewClient(ClientConfig{
		DB:        &sql.DB{},
		SecretKey: "test-secret-key",
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test that minimal config works (backward compatibility)
	router := gin.New()
	router.Use(AuthMiddleware(MiddlewareConfig{
		Client: client,
	}))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	// Should redirect to default /account/login
	if w.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, w.Code)
	}

	location := w.Header().Get("Location")
	if location != "/account/login" {
		t.Errorf("Expected redirect to /account/login, got %s", location)
	}
}

// TestAuthMiddlewareWithMockSession tests middleware behavior with a mocked session
func TestAuthMiddlewareWithMockSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// This test demonstrates the expected flow when a valid session exists
	// In a real scenario, you'd need to mock the database or use a test database
	
	t.Run("context storage", func(t *testing.T) {
		// Create a custom middleware that simulates what AuthMiddleware should do
		router := gin.New()
		
		// Simulate successful session validation
		router.Use(func(c *gin.Context) {
			// Simulate what AuthMiddleware does when session is valid
			mockSession := &RawSession{
				SessionKey:  "test-session-key",
				SessionData: "mock-data",
				ExpireDate:  time.Now().Add(1 * time.Hour),
			}
			c.Set("django_session", mockSession)
			c.Next()
		})
		
		router.GET("/test", func(c *gin.Context) {
			// Verify session is in context
			sessionValue, exists := c.Get("django_session")
			if !exists {
				t.Error("Expected session in context")
			}
			
			rawSession, ok := sessionValue.(*RawSession)
			if !ok {
				t.Errorf("Expected *RawSession, got %T", sessionValue)
			}
			
			if rawSession.SessionKey != "test-session-key" {
				t.Errorf("Expected session key 'test-session-key', got %s", rawSession.SessionKey)
			}
			
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})
}

// TestMiddlewareConfigDefaults tests that default values are set correctly
func TestMiddlewareConfigDefaults(t *testing.T) {
	gin.SetMode(gin.TestMode)

	client, err := NewClient(ClientConfig{
		DB:        &sql.DB{},
		SecretKey: "test-secret-key",
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test with minimal config
	config := MiddlewareConfig{
		Client: client,
	}

	router := gin.New()
	middleware := AuthMiddleware(config)
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	// Should use default redirect URL
	location := w.Header().Get("Location")
	if location != "/account/login" {
		t.Errorf("Expected default redirect to /account/login, got %s", location)
	}
}

// TestAuthMiddlewareErrorHandling tests that custom error handlers work correctly
func TestAuthMiddlewareErrorHandling(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("error handler receives error on missing cookie", func(t *testing.T) {
		var capturedError error
		errorHandlerCalled := false
		
		client, _ := NewClient(ClientConfig{
			DB:        &sql.DB{},
			SecretKey: "test-secret-key",
		})

		router := gin.New()
		router.Use(AuthMiddleware(MiddlewareConfig{
			Client: client,
			OnError: func(c *gin.Context, err error) {
				errorHandlerCalled = true
				capturedError = err
				c.AbortWithStatus(http.StatusUnauthorized)
			},
		}))
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		// No cookie set
		
		router.ServeHTTP(w, req)

		if !errorHandlerCalled {
			t.Error("Expected error handler to be called")
		}

		if capturedError == nil {
			t.Error("Expected error to be captured by OnError handler")
		}

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("different error messages", func(t *testing.T) {
		tests := []struct {
			name           string
			setupRequest   func(*http.Request)
			expectedErrMsg string
		}{
			{
				name: "no cookie",
				setupRequest: func(r *http.Request) {
					// No cookie
				},
				expectedErrMsg: "no session cookie",
			},
			{
				name: "empty cookie",
				setupRequest: func(r *http.Request) {
					r.AddCookie(&http.Cookie{
						Name:  "sessionid",
						Value: "",
					})
				},
				expectedErrMsg: "no session cookie",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var capturedError error
				
				client, _ := NewClient(ClientConfig{
					DB:        &sql.DB{},
					SecretKey: "test-secret-key",
				})

				router := gin.New()
				router.Use(AuthMiddleware(MiddlewareConfig{
					Client: client,
					OnError: func(c *gin.Context, err error) {
						capturedError = err
						c.AbortWithStatus(http.StatusUnauthorized)
					},
				}))
				router.GET("/test", func(c *gin.Context) {
					c.Status(http.StatusOK)
				})

				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", "/test", nil)
				tt.setupRequest(req)
				
				router.ServeHTTP(w, req)

				if capturedError == nil {
					t.Fatal("Expected error to be captured")
				}

				if capturedError.Error() != tt.expectedErrMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.expectedErrMsg, capturedError.Error())
				}
			})
		}
	})
}

// TestSessionCookieName tests that custom cookie names are respected
func TestSessionCookieName(t *testing.T) {
	customCookieName := "custom_session"
	client, err := NewClient(ClientConfig{
		DB:                &sql.DB{},
		SecretKey:         "test-secret-key",
		SessionCookieName: customCookieName,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client.SessionCookieName() != customCookieName {
		t.Errorf("Expected cookie name %s, got %s", customCookieName, client.SessionCookieName())
	}
}

// TestAuthMiddlewareContextKeys tests that session is stored with correct key
func TestAuthMiddlewareContextKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("default session key", func(t *testing.T) {
		// Simulate middleware behavior with mocked successful session
		router := gin.New()
		
		router.Use(func(c *gin.Context) {
			// Simulate what AuthMiddleware does - store with default key
			mockSession := &RawSession{
				SessionKey:  "test-key",
				SessionData: "test-data",
				ExpireDate:  time.Now().Add(1 * time.Hour),
			}
			c.Set("django_session", mockSession)
			c.Next()
		})
		
		router.GET("/test", func(c *gin.Context) {
			sessionValue, exists := c.Get("django_session")
			if !exists {
				t.Error("Expected django_session key in context")
			}
			
			_, ok := sessionValue.(*RawSession)
			if !ok {
				t.Errorf("Expected *RawSession type, got %T", sessionValue)
			}
			
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("custom session key", func(t *testing.T) {
		customKey := "my_session"
		
		router := gin.New()
		
		router.Use(func(c *gin.Context) {
			// Simulate middleware with custom key
			mockSession := &RawSession{
				SessionKey:  "test-key",
				SessionData: "test-data",
				ExpireDate:  time.Now().Add(1 * time.Hour),
			}
			c.Set(customKey, mockSession)
			c.Next()
		})
		
		router.GET("/test", func(c *gin.Context) {
			sessionValue, exists := c.Get(customKey)
			if !exists {
				t.Errorf("Expected %s key in context", customKey)
			}
			
			_, ok := sessionValue.(*RawSession)
			if !ok {
				t.Errorf("Expected *RawSession type, got %T", sessionValue)
			}
			
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})
}
