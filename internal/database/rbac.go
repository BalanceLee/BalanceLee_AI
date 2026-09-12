package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	RBACScopeAll      = "all"
	RBACScopeAssigned = "assigned"
	RBACScopeOwn      = "own"

	RBACMaxBatchResourceAssignments = 100
)

var rbacAssignableResourceTables = map[string]string{
	"project":       "projects",
	"conversation":  "conversations",
	"vulnerability": "vulnerabilities",
	"asset":         "assets",
	"webshell":      "webshell_connections",
	"batch_task":    "batch_task_queues",
	"c2_listener":   "c2_listeners",
}

// RBACUser is a local platform account.
type RBACUser struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"displayName,omitempty"`
	PasswordHash string    `json:"-"`
	Enabled      bool      `json:"enabled"`
	IsBuiltin    bool      `json:"isBuiltin"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// RBACAccess is the resource access context for the built-in admin account.
type RBACAccess struct {
	User             RBACUser          `json:"user"`
	Permissions      map[string]bool   `json:"permissions"`
	PermissionScopes map[string]string `json:"permissionScopes,omitempty"`
	Scope            string            `json:"scope"`
}

func (db *DB) initRBACTables() error {
	// 单用户模式只保留登录凭据表。角色、权限、资源授权和机器人绑定
	// 表属于多人部署功能，不再初始化；旧数据库中的表不会被主动删除。
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS rbac_users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL DEFAULT '',
			password_hash TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			is_builtin INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);`,
		// Kept as a lightweight compatibility table for legacy owner-assignment
		// write paths; single-user authorization never reads it.
		`CREATE TABLE IF NOT EXISTS rbac_resource_assignments (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			UNIQUE(user_id, resource_type, resource_id)
		);`,
		`CREATE TABLE IF NOT EXISTS chat_upload_artifacts (
			relative_path TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			owner_user_id TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS c2_payload_artifacts (
			filename TEXT PRIMARY KEY,
			payload_id TEXT NOT NULL,
			listener_id TEXT NOT NULL,
			owner_user_id TEXT NOT NULL,
			created_at DATETIME NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_chat_upload_artifacts_conversation ON chat_upload_artifacts(conversation_id);`,
		`CREATE INDEX IF NOT EXISTS idx_chat_upload_artifacts_owner ON chat_upload_artifacts(owner_user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_c2_payload_artifacts_listener ON c2_payload_artifacts(listener_id);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) migrateRBACOwnershipColumns() error {
	for _, col := range []struct {
		table string
		name  string
		stmt  string
	}{
		{"projects", "owner_user_id", "ALTER TABLE projects ADD COLUMN owner_user_id TEXT"},
		{"conversations", "owner_user_id", "ALTER TABLE conversations ADD COLUMN owner_user_id TEXT"},
		{"vulnerabilities", "owner_user_id", "ALTER TABLE vulnerabilities ADD COLUMN owner_user_id TEXT"},
		{"webshell_connections", "owner_user_id", "ALTER TABLE webshell_connections ADD COLUMN owner_user_id TEXT"},
		{"batch_task_queues", "owner_user_id", "ALTER TABLE batch_task_queues ADD COLUMN owner_user_id TEXT"},
		{"c2_listeners", "owner_user_id", "ALTER TABLE c2_listeners ADD COLUMN owner_user_id TEXT"},
		{"tool_executions", "owner_user_id", "ALTER TABLE tool_executions ADD COLUMN owner_user_id TEXT"},
		{"tool_executions", "conversation_id", "ALTER TABLE tool_executions ADD COLUMN conversation_id TEXT"},
	} {
		if err := db.addColumnIfMissing(col.table, col.name, col.stmt); err != nil {
			return err
		}
	}
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_tool_executions_owner ON tool_executions(owner_user_id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_tool_executions_conversation ON tool_executions(conversation_id)`)
	return nil
}

func (db *DB) addColumnIfMissing(table, name, stmt string) error {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", table, name).Scan(&count)
	if err != nil || count == 0 {
		if _, addErr := db.Exec(stmt); addErr != nil {
			msg := strings.ToLower(addErr.Error())
			if !strings.Contains(msg, "duplicate column") && !strings.Contains(msg, "already exists") {
				return fmt.Errorf("添加%s.%s字段失败: %w", table, name, addErr)
			}
		}
	}
	return nil
}

// AdminNeedsPassword reports whether the built-in admin account still needs an initial password.
func (db *DB) AdminNeedsPassword() (bool, error) {
	var userCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM rbac_users`).Scan(&userCount); err != nil {
		return false, err
	}
	if userCount == 0 {
		return true, nil
	}
	var hash sql.NullString
	err := db.QueryRow(`
		SELECT password_hash FROM rbac_users
		WHERE username = 'admin' AND is_builtin = 1
		LIMIT 1
	`).Scan(&hash)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !hash.Valid || strings.TrimSpace(hash.String) == "", nil
}

// BootstrapAdmin initializes the single built-in admin credential.
func (db *DB) BootstrapAdmin(adminPasswordHash string) error {
	now := time.Now()
	var userCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM rbac_users`).Scan(&userCount); err != nil {
		return err
	}
	if userCount == 0 {
		if strings.TrimSpace(adminPasswordHash) == "" {
			return errors.New("admin password hash is required for initial bootstrap")
		}
		_, err := db.Exec(`INSERT INTO rbac_users (id, username, display_name, password_hash, enabled, is_builtin, created_at, updated_at) VALUES ('admin', 'admin', 'admin', ?, 1, 1, ?, ?)`, adminPasswordHash, now, now)
		return err
	}
	if strings.TrimSpace(adminPasswordHash) == "" {
		return nil
	}
	_, err := db.Exec(`UPDATE rbac_users SET password_hash = ?, updated_at = ? WHERE username = 'admin' AND is_builtin = 1 AND (password_hash = '' OR password_hash IS NULL)`, adminPasswordHash, now)
	return err
}

func (db *DB) GetRBACUserByUsername(username string) (*RBACUser, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	if username == "" {
		return nil, sql.ErrNoRows
	}
	return db.scanRBACUser(db.QueryRow(`
		SELECT id, username, display_name, password_hash, enabled, is_builtin, created_at, updated_at
		FROM rbac_users WHERE username = ?
	`, username))
}

func (db *DB) GetRBACUserByID(id string) (*RBACUser, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, sql.ErrNoRows
	}
	return db.scanRBACUser(db.QueryRow(`
		SELECT id, username, display_name, password_hash, enabled, is_builtin, created_at, updated_at
		FROM rbac_users WHERE id = ?
	`, id))
}

func (db *DB) scanRBACUser(row *sql.Row) (*RBACUser, error) {
	var u RBACUser
	var enabled, builtin int
	var createdAt, updatedAt string
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &enabled, &builtin, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	u.Enabled = enabled != 0
	u.IsBuiltin = builtin != 0
	u.CreatedAt = parseDBTime(createdAt)
	u.UpdatedAt = parseDBTime(updatedAt)
	return &u, nil
}

func (db *DB) ResolveRBACAccess(userID string) (*RBACAccess, error) {
	u, err := db.GetRBACUserByID(userID)
	if err != nil {
		return nil, err
	}
	return &RBACAccess{
		User:             *u,
		Permissions:      map[string]bool{},
		PermissionScopes: map[string]string{},
		Scope:            RBACScopeAll,
	}, nil
}

func (db *DB) UserCanAccessResource(userID, scope, resourceType, resourceID string) bool {
	userID = strings.TrimSpace(userID)
	resourceType = strings.TrimSpace(resourceType)
	resourceID = strings.TrimSpace(resourceID)
	if userID == "" || resourceType == "" || resourceID == "" {
		return false
	}
	if scope == RBACScopeAll {
		return true
	}
	if scope == RBACScopeOwn {
		if db.userOwnsResource(userID, resourceType, resourceID) {
			return true
		}
	}
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM rbac_resource_assignments WHERE user_id = ? AND resource_type = ? AND resource_id = ?`, userID, resourceType, resourceID).Scan(&n)
	if err == nil && n > 0 {
		return true
	}
	if resourceType == "vulnerability" {
		return db.userCanAccessVulnerabilityViaParent(userID, scope, resourceID)
	}
	if resourceType == "asset" {
		return db.userCanAccessAssetViaParent(userID, scope, resourceID)
	}
	if resourceType == "conversation" {
		return db.userCanAccessConversationViaParent(userID, scope, resourceID)
	}
	if strings.HasPrefix(resourceType, "c2_") {
		return db.userCanAccessC2ViaParent(userID, scope, resourceType, resourceID)
	}
	return false
}

func (db *DB) userCanAccessAssetViaParent(userID, scope, assetID string) bool {
	var projectID sql.NullString
	if err := db.QueryRow(`SELECT project_id FROM assets WHERE id = ?`, assetID).Scan(&projectID); err != nil {
		return false
	}
	return projectID.Valid && strings.TrimSpace(projectID.String) != "" &&
		db.UserCanAccessResource(userID, scope, "project", strings.TrimSpace(projectID.String))
}

func (db *DB) userCanAccessConversationViaParent(userID, scope, conversationID string) bool {
	var projectID sql.NullString
	if err := db.QueryRow(`SELECT project_id FROM conversations WHERE id = ?`, conversationID).Scan(&projectID); err != nil {
		return false
	}
	return projectID.Valid && strings.TrimSpace(projectID.String) != "" &&
		db.UserCanAccessResource(userID, scope, "project", strings.TrimSpace(projectID.String))
}

func (db *DB) userCanAccessVulnerabilityViaParent(userID, scope, vulnerabilityID string) bool {
	var projectID, conversationID sql.NullString
	err := db.QueryRow(`SELECT project_id, conversation_id FROM vulnerabilities WHERE id = ?`, vulnerabilityID).Scan(&projectID, &conversationID)
	if err != nil {
		return false
	}
	if projectID.Valid && strings.TrimSpace(projectID.String) != "" && db.UserCanAccessResource(userID, scope, "project", strings.TrimSpace(projectID.String)) {
		return true
	}
	if conversationID.Valid && strings.TrimSpace(conversationID.String) != "" && db.UserCanAccessResource(userID, scope, "conversation", strings.TrimSpace(conversationID.String)) {
		return true
	}
	return false
}

func (db *DB) UserCanAccessMessage(userID, scope, messageID string) bool {
	var conversationID string
	err := db.QueryRow(`SELECT conversation_id FROM messages WHERE id = ?`, strings.TrimSpace(messageID)).Scan(&conversationID)
	if err != nil {
		return false
	}
	return db.UserCanAccessResource(userID, scope, "conversation", conversationID)
}

func (db *DB) UserCanAccessProcessDetail(userID, scope, processDetailID string) bool {
	var conversationID string
	err := db.QueryRow(`SELECT conversation_id FROM process_details WHERE id = ?`, strings.TrimSpace(processDetailID)).Scan(&conversationID)
	if err != nil {
		return false
	}
	return db.UserCanAccessResource(userID, scope, "conversation", conversationID)
}

func (db *DB) userCanAccessC2ViaParent(userID, scope, resourceType, resourceID string) bool {
	switch resourceType {
	case "c2_session":
		var listenerID string
		if err := db.QueryRow(`SELECT listener_id FROM c2_sessions WHERE id = ?`, resourceID).Scan(&listenerID); err != nil {
			return false
		}
		return db.UserCanAccessResource(userID, scope, "c2_listener", listenerID)
	case "c2_task":
		var sessionID string
		if err := db.QueryRow(`SELECT session_id FROM c2_tasks WHERE id = ?`, resourceID).Scan(&sessionID); err != nil {
			return false
		}
		return db.UserCanAccessResource(userID, scope, "c2_session", sessionID)
	case "c2_file":
		var sessionID string
		if err := db.QueryRow(`SELECT session_id FROM c2_files WHERE id = ?`, resourceID).Scan(&sessionID); err != nil {
			return false
		}
		return db.UserCanAccessResource(userID, scope, "c2_session", sessionID)
	case "c2_event":
		var sessionID, taskID sql.NullString
		if err := db.QueryRow(`SELECT session_id, task_id FROM c2_events WHERE id = ?`, resourceID).Scan(&sessionID, &taskID); err != nil {
			return false
		}
		if sessionID.Valid && strings.TrimSpace(sessionID.String) != "" {
			return db.UserCanAccessResource(userID, scope, "c2_session", strings.TrimSpace(sessionID.String))
		}
		if taskID.Valid && strings.TrimSpace(taskID.String) != "" {
			return db.UserCanAccessResource(userID, scope, "c2_task", strings.TrimSpace(taskID.String))
		}
	}
	return false
}

func (db *DB) userOwnsResource(userID, resourceType, resourceID string) bool {
	table := ""
	switch resourceType {
	case "project":
		table = "projects"
	case "conversation":
		table = "conversations"
	case "vulnerability":
		table = "vulnerabilities"
	case "asset":
		table = "assets"
	case "webshell":
		table = "webshell_connections"
	case "batch_task":
		table = "batch_task_queues"
	case "c2_listener":
		table = "c2_listeners"
	default:
		return false
	}
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE id = ? AND owner_user_id = ?`, resourceID, userID).Scan(&n)
	return err == nil && n > 0
}

func (db *DB) SetResourceOwner(resourceType, resourceID, userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}
	table := ""
	switch resourceType {
	case "project":
		table = "projects"
	case "conversation":
		table = "conversations"
	case "vulnerability":
		table = "vulnerabilities"
	case "asset":
		table = "assets"
	case "webshell":
		table = "webshell_connections"
	case "batch_task":
		table = "batch_task_queues"
	case "c2_listener":
		table = "c2_listeners"
	default:
		return nil
	}
	_, err := db.Exec(`UPDATE `+table+` SET owner_user_id = COALESCE(NULLIF(owner_user_id, ''), ?) WHERE id = ?`, userID, resourceID)
	return err
}

func (db *DB) GetResourceOwner(resourceType, resourceID string) string {
	table := ""
	switch strings.TrimSpace(resourceType) {
	case "project":
		table = "projects"
	case "conversation":
		table = "conversations"
	case "vulnerability":
		table = "vulnerabilities"
	case "asset":
		table = "assets"
	case "webshell":
		table = "webshell_connections"
	case "batch_task":
		table = "batch_task_queues"
	case "c2_listener":
		table = "c2_listeners"
	default:
		return ""
	}
	var owner sql.NullString
	if err := db.QueryRow(`SELECT owner_user_id FROM `+table+` WHERE id = ?`, strings.TrimSpace(resourceID)).Scan(&owner); err != nil {
		return ""
	}
	return strings.TrimSpace(owner.String)
}

func (db *DB) AssignResourceToUser(userID, resourceType, resourceID string) error {
	_, err := db.AssignResourcesToUser(userID, resourceType, []string{resourceID})
	return err
}

// AssignResourcesToUser validates the complete request before writing anything,
// then inserts all grants in one transaction. Existing grants are idempotent.
func (db *DB) AssignResourcesToUser(userID, resourceType string, resourceIDs []string) (int64, error) {
	userID = strings.TrimSpace(userID)
	resourceType = strings.TrimSpace(resourceType)
	if userID == "" || resourceType == "" || len(resourceIDs) == 0 {
		return 0, errors.New("user_id, resource_type and resource_ids are required")
	}
	if len(resourceIDs) > RBACMaxBatchResourceAssignments {
		return 0, fmt.Errorf("一次最多授权 %d 个资源", RBACMaxBatchResourceAssignments)
	}
	table, ok := rbacAssignableResourceTables[resourceType]
	if !ok {
		return 0, fmt.Errorf("不支持的资源类型: %s", resourceType)
	}

	uniqueIDs := make([]string, 0, len(resourceIDs))
	seen := make(map[string]struct{}, len(resourceIDs))
	for _, rawID := range resourceIDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			return 0, errors.New("资源 ID 不能为空")
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		uniqueIDs = append(uniqueIDs, id)
	}
	if len(uniqueIDs) == 0 {
		return 0, errors.New("资源 ID 不能为空")
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var userExists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM rbac_users WHERE id = ?`, userID).Scan(&userExists); err != nil {
		return 0, err
	}
	if userExists == 0 {
		return 0, errors.New("用户不存在")
	}
	for _, resourceID := range uniqueIDs {
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE id = ?`, resourceID).Scan(&exists); err != nil {
			return 0, err
		}
		if exists == 0 {
			return 0, fmt.Errorf("资源不存在: %s/%s", resourceType, resourceID)
		}
	}

	var created int64
	for _, resourceID := range uniqueIDs {
		result, err := tx.Exec(`
			INSERT OR IGNORE INTO rbac_resource_assignments (id, user_id, resource_type, resource_id, created_at)
			VALUES (?, ?, ?, ?, ?)
		`, uuid.NewString(), userID, resourceType, resourceID, time.Now())
		if err != nil {
			return 0, err
		}
		if n, err := result.RowsAffected(); err == nil {
			created += n
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return created, nil
}

// AssignResourcesToUserAuto detects each resource's actual type before writing.
// The whole batch is validated first and committed atomically.

func (db *DB) UpdateRBACUserPassword(userID, passwordHash string) error {
	userID = strings.TrimSpace(userID)
	passwordHash = strings.TrimSpace(passwordHash)
	if userID == "" || passwordHash == "" {
		return errors.New("user_id and password_hash are required")
	}
	_, err := db.Exec(`UPDATE rbac_users SET password_hash = ?, updated_at = ? WHERE id = ?`, passwordHash, time.Now(), userID)
	return err
}

func (db *DB) UpdateRBACAdminPassword(passwordHash string) error {
	return db.UpdateRBACUserPassword("admin", passwordHash)
}

// DeleteRBACResourceAssignmentWithDetails atomically removes an assignment and
// returns the deleted row so callers can write a complete, attributable audit
// event without racing a separate lookup against another delete.
