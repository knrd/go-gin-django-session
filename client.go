package django_session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrSessionNotFound is returned when session is not found in database
	ErrSessionNotFound = errors.New("session not found")
	// ErrSessionExpired is returned when session has expired
	ErrSessionExpired = errors.New("session expired")
	// ErrInvalidSignature is returned when session signature is invalid
	ErrInvalidSignature = errors.New("invalid session signature")
	// ErrUserNotFound is returned when user is not found in database
	ErrUserNotFound = errors.New("user not found")
)

// DBTX is an interface compatible with *pgx.Conn, *pgxpool.Pool and the sqlc generated interfaces.
type DBTX interface {
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
	Query(context.Context, string, ...interface{}) (pgx.Rows, error)
	QueryRow(context.Context, string, ...interface{}) pgx.Row
	CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)
}

// RawSession represents a Django session without decoded payload (fast)
type RawSession struct {
	SessionKey  string
	SessionData string
	ExpireDate  time.Time
}

// ClientConfig holds configuration for the Django session client
type ClientConfig struct {
	DB                DBTX
	SecretKey         string
	SessionCookieName string
	MaxAge            time.Duration // Optional: max age for session validation
}

// Client provides methods to interact with Django sessions
type Client struct {
	db                DBTX
	secretKey         string
	sessionCookieName string
	maxAge            time.Duration
	signer            *DjangoSigner
}

// NewClient creates a new Django session client
func NewClient(config ClientConfig) (*Client, error) {
	if config.DB == nil {
		return nil, errors.New("database connection is required")
	}
	if config.SecretKey == "" {
		return nil, errors.New("secret key is required")
	}
	if config.SessionCookieName == "" {
		config.SessionCookieName = "sessionid" // Django default
	}

	signer := &DjangoSigner{
		SecretKey: config.SecretKey,
		Salt:      "django.contrib.sessions.SessionStore",
		Sep:       ":",
		Algorithm: "sha256",
	}

	return &Client{
		db:                config.DB,
		secretKey:         config.SecretKey,
		sessionCookieName: config.SessionCookieName,
		maxAge:            config.MaxAge,
		signer:            signer,
	}, nil
}

// GetRawSession retrieves and validates a Django session by session key
// WITHOUT decoding the payload. This is fast and used by middleware.
func (c *Client) GetRawSession(ctx context.Context, sessionKey string) (*RawSession, error) {
	if sessionKey == "" || len(sessionKey) > 255 {
		return nil, ErrSessionNotFound
	}

	var session RawSession
	query := `SELECT session_key, session_data, expire_date 
	          FROM django_session 
	          WHERE session_key = $1`

	err := c.db.QueryRow(ctx, query, sessionKey).Scan(
		&session.SessionKey,
		&session.SessionData,
		&session.ExpireDate,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("database query failed: %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpireDate) {
		return nil, ErrSessionExpired
	}

	// Return session WITHOUT decoding payload
	return &session, nil
}

// DecodeSessionUserID decodes the session payload and extracts user ID
// Use this when you have a RawSession and need to get the user ID
func (c *Client) DecodeSessionUserID(sessionData string) (string, error) {
	return c.decodeSessionData(sessionData)
}

// decodeSessionData decodes Django session data and extracts user ID
func (c *Client) decodeSessionData(sessionData string) (string, error) {
	var sessionMap map[string]interface{}
	var err error

	if c.maxAge > 0 {
		sessionMap, err = c.signer.UnsignObject(sessionData, &c.maxAge)
	} else {
		sessionMap, err = c.signer.UnsignObject(sessionData, nil)
	}

	if err != nil {
		return "", err
	}

	// Extract _auth_user_id
	userID, ok := sessionMap["_auth_user_id"]
	if !ok {
		return "", errors.New("_auth_user_id not found in session")
	}

	// Convert to string
	switch v := userID.(type) {
	case string:
		return v, nil
	case float64:
		return fmt.Sprintf("%.0f", v), nil
	case int:
		return fmt.Sprintf("%d", v), nil
	default:
		return "", fmt.Errorf("unexpected user ID type: %T", v)
	}
}

// SessionCookieName returns the configured session cookie name
func (c *Client) SessionCookieName() string {
	return c.sessionCookieName
}
