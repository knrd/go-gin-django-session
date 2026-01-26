package django_session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/mock"
)

// MockDBTX is a mock implementation of DBTX
type MockDBTX struct {
	mock.Mock
}

func (m *MockDBTX) Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error) {
	args := m.Called(ctx, sql, arguments)
	return args.Get(0).(pgconn.CommandTag), args.Error(1)
}

func (m *MockDBTX) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	calledArgs := m.Called(ctx, sql, args)
	return calledArgs.Get(0).(pgx.Rows), calledArgs.Error(1)
}

func (m *MockDBTX) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	calledArgs := m.Called(ctx, sql, args)
	return calledArgs.Get(0).(pgx.Row)
}

func (m *MockDBTX) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	args := m.Called(ctx, tableName, columnNames, rowSrc)
	return args.Get(0).(int64), args.Error(1)
}

// MockRow is a mock implementation of pgx.Row
type MockRow struct {
	mock.Mock
}

func (m *MockRow) Scan(dest ...interface{}) error {
	args := m.Called(dest...)
	return args.Error(0)
}

// TestNewClient tests the Client constructor
func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  ClientConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: ClientConfig{
				DB:        &MockDBTX{},
				SecretKey: "test-secret-key",
			},
			wantErr: false,
		},
		{
			name: "missing DB",
			config: ClientConfig{
				SecretKey: "test-secret-key",
			},
			wantErr: true,
			errMsg:  "database connection is required",
		},
		{
			name: "missing secret key",
			config: ClientConfig{
				DB: &MockDBTX{},
			},
			wantErr: true,
			errMsg:  "secret key is required",
		},
		{
			name: "custom cookie name",
			config: ClientConfig{
				DB:                &MockDBTX{},
				SecretKey:         "test-secret-key",
				SessionCookieName: "custom_sessionid",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewClient() expected error but got none")
					return
				}
				if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("NewClient() error = %v, want %v", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("NewClient() unexpected error: %v", err)
				return
			}
			if client == nil {
				t.Errorf("NewClient() returned nil client")
				return
			}

			// Check default cookie name
			if tt.config.SessionCookieName == "" {
				if client.SessionCookieName() != "sessionid" {
					t.Errorf("NewClient() cookie name = %v, want sessionid", client.SessionCookieName())
				}
			} else {
				if client.SessionCookieName() != tt.config.SessionCookieName {
					t.Errorf("NewClient() cookie name = %v, want %v", client.SessionCookieName(), tt.config.SessionCookieName)
				}
			}
		})
	}
}

// TestDecodeSessionData tests the session data decoding
func TestClientDecodeSessionData(t *testing.T) {
	secretKey := "test-secret-key-9k2j3n4l5k6j7h8g9f0d1s2a3f4g5h6j"

	// Create a test session using EncodeSessionData
	testUserID := "12345"
	sessionData, err := EncodeSessionData(testUserID, secretKey, map[string]interface{}{
		"username": "testuser",
	})
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Create client
	client, err := NewClient(ClientConfig{
		DB:        &MockDBTX{},
		SecretKey: secretKey,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test decoding
	userID, err := client.decodeSessionData(sessionData)
	if err != nil {
		t.Errorf("decodeSessionData() error = %v", err)
		return
	}

	if userID != testUserID {
		t.Errorf("decodeSessionData() userID = %v, want %v", userID, testUserID)
	}
}

// TestClientDecodeSessionDataWithMaxAge tests session decoding with max age validation
func TestClientDecodeSessionDataWithMaxAge(t *testing.T) {
	secretKey := "test-secret-key-9k2j3n4l5k6j7h8g9f0d1s2a3f4g5h6j"
	testUserID := "12345"

	// Create a timestamped session
	signer := &DjangoSigner{
		SecretKey: secretKey,
		Salt:      "django.contrib.sessions.SessionStore",
		Sep:       ":",
		Algorithm: "sha256",
	}

	sessionMap := map[string]interface{}{
		"_auth_user_id": testUserID,
		"username":      "testuser",
	}

	sessionData, err := signer.SignObject(sessionMap, true)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	tests := []struct {
		name    string
		maxAge  time.Duration
		wantErr bool
	}{
		{
			name:    "no max age",
			maxAge:  0,
			wantErr: false,
		},
		{
			name:    "valid max age",
			maxAge:  1 * time.Hour,
			wantErr: false,
		},
		{
			name:    "expired - very short max age",
			maxAge:  1 * time.Nanosecond,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Add small delay for the expired test
			if tt.name == "expired - very short max age" {
				time.Sleep(2 * time.Millisecond)
			}

			client, err := NewClient(ClientConfig{
				DB:        &MockDBTX{},
				SecretKey: secretKey,
				MaxAge:    tt.maxAge,
			})
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			userID, err := client.decodeSessionData(sessionData)
			if tt.wantErr {
				if err == nil {
					t.Errorf("decodeSessionData() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("decodeSessionData() unexpected error: %v", err)
				return
			}

			if userID != testUserID {
				t.Errorf("decodeSessionData() userID = %v, want %v", userID, testUserID)
			}
		})
	}
}

// TestErrorConstants tests that error constants are properly defined
func TestErrorConstants(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrSessionNotFound", ErrSessionNotFound},
		{"ErrSessionExpired", ErrSessionExpired},
		{"ErrInvalidSignature", ErrInvalidSignature},
		{"ErrUserNotFound", ErrUserNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}
			if tt.err.Error() == "" {
				t.Errorf("%s has empty error message", tt.name)
			}
		})
	}
}

// TestErrorWrapping tests that errors can be checked with errors.Is
func TestErrorWrapping(t *testing.T) {
	// Test that our custom errors are distinct
	if errors.Is(ErrSessionNotFound, ErrSessionExpired) {
		t.Errorf("Different error types should not be equal")
	}

	// Test that errors.Is works with our sentinel errors
	if !errors.Is(ErrSessionNotFound, ErrSessionNotFound) {
		t.Errorf("ErrSessionNotFound should equal itself")
	}
}

// TestGetRawSession tests the GetRawSession method (used by middleware)
func TestGetRawSession(t *testing.T) {
	ctx := context.Background()

	client, err := NewClient(ClientConfig{
		DB:        &MockDBTX{},
		SecretKey: "test-secret",
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test with empty session key
	_, err = client.GetRawSession(ctx, "")
	if err == nil {
		t.Errorf("GetRawSession() expected error for empty session key")
	}
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("GetRawSession() error = %v, want ErrSessionNotFound", err)
	}
}

func TestGetRawSessionKeyTooLong(t *testing.T) {
	ctx := context.Background()

	client, err := NewClient(ClientConfig{
		DB:        &MockDBTX{},
		SecretKey: "test-secret",
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test with session key too long
	_, err = client.GetRawSession(ctx, strings.Repeat("1", 256))
	if err == nil {
		t.Errorf("GetRawSession() expected error for too long session key")
	}
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("GetRawSession() error = %v, want ErrSessionNotFound", err)
	}
}

// TestDecodeSessionUserID tests the DecodeSessionUserID method (used by handlers)
func TestDecodeSessionUserID(t *testing.T) {
	secretKey := "test-secret-key-9k2j3n4l5k6j7h8g9f0d1s2a3f4g5h6j"
	testUserID := "12345"

	sessionData, err := EncodeSessionData(testUserID, secretKey, nil)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	client, err := NewClient(ClientConfig{
		DB:        &MockDBTX{},
		SecretKey: secretKey,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test decoding
	userID, err := client.DecodeSessionUserID(sessionData)
	if err != nil {
		t.Errorf("DecodeSessionUserID() error = %v", err)
		return
	}

	if userID != testUserID {
		t.Errorf("DecodeSessionUserID() userID = %v, want %v", userID, testUserID)
	}
}

// TestDecodeSessionUserIDWithInvalidData tests error handling
func TestDecodeSessionUserIDWithInvalidData(t *testing.T) {
	client, err := NewClient(ClientConfig{
		DB:        &MockDBTX{},
		SecretKey: "test-secret",
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	tests := []struct {
		name        string
		sessionData string
		wantErr     bool
	}{
		{
			name:        "empty data",
			sessionData: "",
			wantErr:     true,
		},
		{
			name:        "invalid base64",
			sessionData: "not-valid-base64!!!",
			wantErr:     true,
		},
		{
			name:        "valid base64 but invalid signature",
			sessionData: "eyJ0ZXN0IjoidmFsdWUifQ:1234567890abcdef",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.DecodeSessionUserID(tt.sessionData)
			if tt.wantErr && err == nil {
				t.Errorf("DecodeSessionUserID() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("DecodeSessionUserID() unexpected error: %v", err)
			}
		})
	}
}
