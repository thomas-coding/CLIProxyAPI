package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/gin-gonic/gin"
)

// requestIDKey is the context key for storing/retrieving request IDs.
type requestIDKey struct{}

// requestStartTimeKey is the context key for storing/retrieving request start timestamps.
type requestStartTimeKey struct{}

// ginRequestIDKey is the Gin context key for request IDs.
const ginRequestIDKey = "__request_id__"

// ginRequestStartTimeKey is the Gin context key for request start timestamps.
const ginRequestStartTimeKey = "__request_start_time__"

// GenerateRequestID creates a new 8-character hex request ID.
func GenerateRequestID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}

// WithRequestID returns a new context with the request ID attached.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, requestID)
}

// GetRequestID retrieves the request ID from the context.
// Returns empty string if not found.
func GetRequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// WithRequestStartTime returns a new context with the request start time attached.
func WithRequestStartTime(ctx context.Context, start time.Time) context.Context {
	return context.WithValue(ctx, requestStartTimeKey{}, start)
}

// GetRequestStartTime retrieves the request start time from the context.
// Returns zero time if not found.
func GetRequestStartTime(ctx context.Context) time.Time {
	if ctx == nil {
		return time.Time{}
	}
	if start, ok := ctx.Value(requestStartTimeKey{}).(time.Time); ok {
		return start
	}
	return time.Time{}
}

// SetGinRequestID stores the request ID in the Gin context.
func SetGinRequestID(c *gin.Context, requestID string) {
	if c != nil {
		c.Set(ginRequestIDKey, requestID)
	}
}

// GetGinRequestID retrieves the request ID from the Gin context.
func GetGinRequestID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if id, exists := c.Get(ginRequestIDKey); exists {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}

// SetGinRequestStartTime stores the request start time in the Gin context.
func SetGinRequestStartTime(c *gin.Context, start time.Time) {
	if c != nil {
		c.Set(ginRequestStartTimeKey, start)
	}
}

// GetGinRequestStartTime retrieves the request start time from the Gin context.
// Returns zero time if not found.
func GetGinRequestStartTime(c *gin.Context) time.Time {
	if c == nil {
		return time.Time{}
	}
	if start, exists := c.Get(ginRequestStartTimeKey); exists {
		if ts, ok := start.(time.Time); ok {
			return ts
		}
	}
	return time.Time{}
}
