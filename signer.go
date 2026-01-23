package django_session

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// DjangoSigner handles Django's cryptographic signing
type DjangoSigner struct {
	SecretKey string
	Salt      string
	Sep       string
	Algorithm string
}

// NewDjangoSigner creates a new signer with default values matching Django's TimestampSigner
func NewDjangoSigner(secretKey string) *DjangoSigner {
	return &DjangoSigner{
		SecretKey: secretKey,
		Salt:      "django.core.signing",
		Sep:       ":",
		Algorithm: "sha256",
	}
}

// b64Decode decodes URL-safe base64 with padding handling
func b64Decode(s string) ([]byte, error) {
	// Add padding if needed
	padding := (4 - len(s)%4) % 4
	padded := s + strings.Repeat("=", padding)
	return base64.URLEncoding.DecodeString(padded)
}

// b64Encode encodes to URL-safe base64 without padding
func b64Encode(data []byte) string {
	encoded := base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(encoded, "=")
}

// b62Encode encodes a number to base62 (used for timestamps)
func b62Encode(n int64) string {
	if n == 0 {
		return "0"
	}
	sign := ""
	if n < 0 {
		sign = "-"
		n = -n
	}
	encoded := ""
	for n > 0 {
		remainder := n % 62
		encoded = string(base62Alphabet[remainder]) + encoded
		n = n / 62
	}
	return sign + encoded
}

// b62Decode decodes a base62 encoded number (used for timestamps)
func b62Decode(s string) (int64, error) {
	if s == "0" {
		return 0, nil
	}

	sign := int64(1)
	if len(s) > 0 && s[0] == '-' {
		s = s[1:]
		sign = -1
	}

	var decoded int64
	for _, char := range s {
		index := strings.IndexRune(base62Alphabet, char)
		if index == -1 {
			return 0, fmt.Errorf("invalid base62 character: %c", char)
		}
		decoded = decoded*62 + int64(index)
	}

	return sign * decoded, nil
}

// saltedHMAC generates a salted HMAC like Django's salted_hmac function
func (ds *DjangoSigner) saltedHMAC(salt, value string) []byte {
	// Django's salted_hmac implementation:
	// 1. key_salt = hashlib.sha256((salt + secret).encode()).digest()
	// 2. return hmac.new(key_salt, msg=value.encode(), digestmod=hashlib.sha256)

	// Step 1: Derive key from salt + secret using SHA256
	h := sha256.New()
	h.Write([]byte(salt + ds.SecretKey))
	derivedKey := h.Sum(nil)

	// Step 2: HMAC the value with the derived key
	mac := hmac.New(sha256.New, derivedKey)
	mac.Write([]byte(value))

	return mac.Sum(nil)
}

// signature generates a signature for a value
func (ds *DjangoSigner) signature(value string) string {
	// Django's Signer adds "signer" suffix to the salt before calling salted_hmac
	hashBytes := ds.saltedHMAC(ds.Salt+"signer", value)
	return b64Encode(hashBytes)
}

// constantTimeCompare performs constant-time string comparison
func constantTimeCompare(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// Unsign verifies and extracts the original value from a signed string
func (ds *DjangoSigner) Unsign(signedValue string) (string, error) {
	if !strings.Contains(signedValue, ds.Sep) {
		return "", errors.New("no separator found in value")
	}

	// Split from the right to get the last separator
	lastSepIndex := strings.LastIndex(signedValue, ds.Sep)
	value := signedValue[:lastSepIndex]
	sig := signedValue[lastSepIndex+1:]

	// Verify signature
	expectedSig := ds.signature(value)
	if !constantTimeCompare(sig, expectedSig) {
		return "", fmt.Errorf("signature does not match")
	}

	return value, nil
}

// UnsignTimestamp verifies and extracts value from a timestamped signed string
func (ds *DjangoSigner) UnsignTimestamp(signedValue string, maxAge *time.Duration) (string, error) {
	// First unsign to verify the signature
	result, err := ds.Unsign(signedValue)
	if err != nil {
		return "", err
	}

	// Split to get value and timestamp
	if !strings.Contains(result, ds.Sep) {
		return "", errors.New("no timestamp separator found")
	}

	lastSepIndex := strings.LastIndex(result, ds.Sep)
	value := result[:lastSepIndex]
	timestampStr := result[lastSepIndex+1:]

	// Decode base62 timestamp
	timestamp, err := b62Decode(timestampStr)
	if err != nil {
		return "", fmt.Errorf("invalid timestamp: %w", err)
	}

	// Check age if maxAge is specified
	if maxAge != nil {
		age := time.Since(time.Unix(timestamp, 0))
		if age > *maxAge {
			return "", fmt.Errorf("signature age %v > %v", age, *maxAge)
		}
	}

	return value, nil
}

// SignTimestamp signs a value with a timestamp
func (ds *DjangoSigner) SignTimestamp(value string) string {
	timestamp := time.Now().Unix()
	timestampB62 := b62Encode(timestamp)
	valueWithTimestamp := value + ds.Sep + timestampB62
	sig := ds.signature(valueWithTimestamp)
	return valueWithTimestamp + ds.Sep + sig
}

// SignObject encodes and signs a map as JSON with timestamp and optional compression
func (ds *DjangoSigner) SignObject(obj map[string]interface{}, compress bool) (string, error) {
	// Marshal to JSON
	jsonData, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("json encode error: %w", err)
	}

	var dataToEncode []byte
	var prefix string

	// Compress if requested
	if compress {
		var buf bytes.Buffer
		writer := zlib.NewWriter(&buf)
		_, err := writer.Write(jsonData)
		if err != nil {
			writer.Close()
			return "", fmt.Errorf("zlib compress error: %w", err)
		}
		writer.Close()
		dataToEncode = buf.Bytes()
		prefix = "."
	} else {
		dataToEncode = jsonData
		prefix = ""
	}

	// Encode to base64
	base64Data := prefix + b64Encode(dataToEncode)

	// Sign with timestamp
	return ds.SignTimestamp(base64Data), nil
}

// UnsignObject decodes a signed object (JSON)
func (ds *DjangoSigner) UnsignObject(signedObj string, maxAge *time.Duration) (map[string]interface{}, error) {
	// Unsign with timestamp verification
	var base64Data string
	var err error

	if maxAge != nil {
		base64Data, err = ds.UnsignTimestamp(signedObj, maxAge)
	} else {
		base64Data, err = ds.UnsignTimestamp(signedObj, nil)
	}

	if err != nil {
		return nil, err
	}

	// Check if compressed (starts with '.')
	decompress := false
	if len(base64Data) > 0 && base64Data[0] == '.' {
		decompress = true
		base64Data = base64Data[1:]
	}

	// Decode base64
	data, err := b64Decode(base64Data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %w", err)
	}

	// Decompress if needed
	if decompress {
		reader, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("zlib decompress error: %w", err)
		}
		defer reader.Close()

		decompressed, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("zlib read error: %w", err)
		}
		data = decompressed
	}

	// Parse JSON
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("json decode error: %w", err)
	}

	return result, nil
}

// DecodeSessionData decodes Django session data and returns the user ID
// Uses the default salt for Django sessions: "django.contrib.sessions.SessionStore"
func DecodeSessionData(sessionData, secretKey string) (string, error) {
	return DecodeSessionDataWithMaxAge(sessionData, secretKey, 0)
}

// DecodeSessionDataWithMaxAge decodes Django session data with timestamp validation
func DecodeSessionDataWithMaxAge(sessionData, secretKey string, maxAgeSeconds int) (string, error) {
	// Django sessions use a specific salt
	return DecodeSessionDataWithSalt(sessionData, secretKey, "django.contrib.sessions.SessionStore", maxAgeSeconds)
}

// DecodeSessionDataWithSalt decodes Django session data with custom salt and timestamp validation
func DecodeSessionDataWithSalt(sessionData, secretKey, salt string, maxAgeSeconds int) (string, error) {
	signer := &DjangoSigner{
		SecretKey: secretKey,
		Salt:      salt,
		Sep:       ":",
		Algorithm: "sha256",
	}

	// Decode the session object with optional max age check
	var sessionMap map[string]interface{}
	var err error

	if maxAgeSeconds > 0 {
		maxAge := time.Duration(maxAgeSeconds) * time.Second
		sessionMap, err = signer.UnsignObject(sessionData, &maxAge)
	} else {
		sessionMap, err = signer.UnsignObject(sessionData, nil)
	}

	if err != nil {
		return "", fmt.Errorf("failed to unsign session: %w", err)
	}

	// Extract _auth_user_id
	userID, ok := sessionMap["_auth_user_id"]
	if !ok {
		return "", errors.New("_auth_user_id not found in session")
	}

	// Convert to string (might be string or number)
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

// EncodeSessionData creates a new Django session with the given user ID and additional data
func EncodeSessionData(userID string, secretKey string, additionalData map[string]interface{}) (string, error) {
	return EncodeSessionDataWithSalt(userID, secretKey, "django.contrib.sessions.SessionStore", additionalData, true)
}

// EncodeSessionDataWithSalt creates a new Django session with custom salt
func EncodeSessionDataWithSalt(userID string, secretKey string, salt string, additionalData map[string]interface{}, compress bool) (string, error) {
	signer := &DjangoSigner{
		SecretKey: secretKey,
		Salt:      salt,
		Sep:       ":",
		Algorithm: "sha256",
	}

	// Create session data map
	sessionData := make(map[string]interface{})
	sessionData["_auth_user_id"] = userID

	// Add additional data
	for key, value := range additionalData {
		sessionData[key] = value
	}

	// Sign the object
	return signer.SignObject(sessionData, compress)
}

// UpdateSessionData modifies an existing session by decoding, updating fields, and re-encoding
func UpdateSessionData(sessionData string, secretKey string, updates map[string]interface{}) (string, error) {
	return UpdateSessionDataWithSalt(sessionData, secretKey, "django.contrib.sessions.SessionStore", updates, true)
}

// UpdateSessionDataWithSalt modifies an existing session with custom salt
func UpdateSessionDataWithSalt(sessionData string, secretKey string, salt string, updates map[string]interface{}, compress bool) (string, error) {
	signer := &DjangoSigner{
		SecretKey: secretKey,
		Salt:      salt,
		Sep:       ":",
		Algorithm: "sha256",
	}

	// Decode existing session
	existingData, err := signer.UnsignObject(sessionData, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decode existing session: %w", err)
	}

	// Apply updates
	for key, value := range updates {
		if value == nil {
			// nil means delete the key
			delete(existingData, key)
		} else {
			existingData[key] = value
		}
	}

	// Re-sign the updated data
	return signer.SignObject(existingData, compress)
}
