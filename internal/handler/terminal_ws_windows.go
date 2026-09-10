//go:build windows

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/UserExistsError/conpty"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type windowsTerminalResize struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

var windowsTerminalUpgrader = websocket.Upgrader{
	CheckOrigin: func(_ *http.Request) bool { return true },
}

func windowsTerminalShell() string {
	for _, candidate := range []string{"pwsh.exe", "powershell.exe", "cmd.exe"} {
		if path, err := exec.LookPath(candidate); err == nil {
			if candidate == "pwsh.exe" || candidate == "powershell.exe" {
				return fmt.Sprintf(`"%s" -NoLogo`, path)
			}
			return fmt.Sprintf(`"%s"`, path)
		}
	}
	return "cmd.exe"
}

// RunCommandWS provides a persistent interactive Windows shell through ConPTY.
func (h *TerminalHandler) RunCommandWS(c *gin.Context) {
	conn, err := windowsTerminalUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	workDir, _ := os.Getwd()
	pty, err := conpty.Start(
		windowsTerminalShell(),
		conpty.ConPtyDimensions(80, 24),
		conpty.ConPtyWorkDir(workDir),
		conpty.ConPtyEnv(os.Environ()),
	)
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("Unable to start Windows terminal: "+err.Error()+"\r\n"))
		return
	}
	defer pty.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, readErr := pty.Read(buffer)
			if n > 0 {
				if writeErr := conn.WriteMessage(websocket.BinaryMessage, buffer[:n]); writeErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	conn.SetReadLimit(64 * 1024)
	_ = conn.SetReadDeadline(time.Now().Add(terminalTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(terminalTimeout))
	})
	for {
		messageType, data, readErr := conn.ReadMessage()
		if readErr != nil {
			break
		}
		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
			continue
		}
		if messageType == websocket.TextMessage && len(data) > 0 && data[0] == '{' {
			var resize windowsTerminalResize
			if json.Unmarshal(data, &resize) == nil && resize.Type == "resize" && resize.Cols > 0 && resize.Rows > 0 {
				_ = pty.Resize(int(resize.Cols), int(resize.Rows))
				continue
			}
		}
		if len(data) > 0 {
			if _, writeErr := pty.Write(data); writeErr != nil {
				break
			}
		}
	}

	_ = pty.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _ = pty.Wait(waitCtx)
}
