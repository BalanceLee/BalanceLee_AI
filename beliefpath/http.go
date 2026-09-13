package beliefpath

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(group *gin.RouterGroup, service *Service) {
	if group == nil || service == nil {
		return
	}
	group.GET("/beliefpath/status", func(c *gin.Context) {
		cfg := service.Config()
		c.JSON(http.StatusOK, gin.H{
			"enabled": cfg.Enabled,
			"active":  service.Active(),
			"mode":    cfg.Mode,
			"variant": cfg.Variant,
			"config":  cfg,
		})
	})
	group.DELETE("/beliefpath/learning", func(c *gin.Context) {
		if err := service.ResetLearning(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "BeliefPath learning state reset"})
	})
	group.GET("/beliefpath/:conversationId/snapshot", func(c *gin.Context) {
		conversationID := strings.TrimSpace(c.Param("conversationId"))
		if conversationID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "conversationId is required"})
			return
		}
		snapshot, err := service.Snapshot(c.Request.Context(), conversationID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if snapshot == nil {
			c.JSON(http.StatusOK, gin.H{
				"conversation_id": conversationID,
				"mode":            ModeOff,
				"nodes":           []Node{},
				"edges":           []Edge{},
				"hyperedges":      []Hyperedge{},
			})
			return
		}
		c.JSON(http.StatusOK, snapshot)
	})
	group.GET("/beliefpath/:conversationId/summary", func(c *gin.Context) {
		conversationID := strings.TrimSpace(c.Param("conversationId"))
		if conversationID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "conversationId is required"})
			return
		}
		summary, err := service.BuildSummary(
			c.Request.Context(),
			conversationID,
			strings.TrimSpace(c.Query("messageId")),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if summary == nil {
			c.JSON(http.StatusOK, gin.H{"available": false})
			return
		}
		c.JSON(http.StatusOK, summary)
	})
	group.DELETE("/beliefpath/:conversationId", func(c *gin.Context) {
		conversationID := strings.TrimSpace(c.Param("conversationId"))
		if conversationID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "conversationId is required"})
			return
		}
		if err := service.ResetConversation(c.Request.Context(), conversationID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "BeliefPath state reset"})
	})
}
