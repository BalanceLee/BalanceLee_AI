package app

import (
	"balancelee-ai/internal/config"
	"balancelee-ai/internal/mcp"
	"balancelee-ai/internal/vision"

	"go.uber.org/zap"
)

func registerVisionTools(mcpServer *mcp.Server, cfg *config.Config, logger *zap.Logger) {
	vision.RegisterAnalyzeImageTool(mcpServer, cfg, logger)
}
