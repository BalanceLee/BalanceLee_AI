package security

import (
	"path/filepath"
	"testing"

	"balancelee-ai/internal/database"

	"go.uber.org/zap"
)

func TestAttachAdminStoreBootstrapsAdminPassword(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "auth-bootstrap.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewAuthManager(12)
	generated, err := manager.AttachAdminStore(db)
	if err != nil {
		t.Fatalf("AttachAdminStore: %v", err)
	}
	if generated == "" {
		t.Fatal("expected generated admin password on first bootstrap")
	}
	if !manager.CheckUserPassword("admin", generated) {
		t.Fatal("generated password should authenticate admin")
	}

	second, err := manager.AttachAdminStore(db)
	if err != nil {
		t.Fatalf("AttachAdminStore second call: %v", err)
	}
	if second != "" {
		t.Fatalf("expected no password on second bootstrap, got %q", second)
	}
}
