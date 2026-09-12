package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestQueryTokenOnlyAllowedForSSEAndWebSocketGET(t *testing.T) {
	requestToken := func(method, accept, upgrade string) string {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(method, "/api/test?token=secret", nil)
		c.Request.Header.Set("Accept", accept)
		c.Request.Header.Set("Upgrade", upgrade)
		return extractTokenFromRequest(c)
	}
	if got := requestToken(http.MethodGet, "application/json", ""); got != "" {
		t.Fatalf("ordinary GET accepted query token %q", got)
	}
	if got := requestToken(http.MethodPost, "text/event-stream", ""); got != "" {
		t.Fatalf("POST accepted query token %q", got)
	}
	if got := requestToken(http.MethodGet, "text/event-stream", ""); got != "secret" {
		t.Fatalf("SSE token = %q", got)
	}
	if got := requestToken(http.MethodGet, "", "websocket"); got != "secret" {
		t.Fatalf("WebSocket token = %q", got)
	}
}
