package permissionbundle

// OPTIONAL / NON-PRODUCTION (v45). The external-authority types in this file
// (RecoveryFenceV1, ElectedAuthoritySession, ExternalAuthorityDriver,
// FencedAuthorityAdapter) are retained as historical interfaces and synthetic
// test seams. They are not a delivery prerequisite and no operator is required
// to provision an external fence, election or recovery service. They are not
// wired into live startup with a no-op, and nothing here claims restore-safe
// acknowledged-state recovery for ordinary SQL.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gocraft/dbr/v2"
)

const (
	AuthorityModeExternalFencedV1     = "external_fenced_v1"
	AuthorityModeNativeSingleWriterV1 = "native_single_writer_lineage_v1"

	NativeAuthorityLineageTable = "bot_permission_authority_lineage"

	NativeAuthorityLineageDDL = `CREATE TABLE IF NOT EXISTS bot_permission_authority_lineage (
		singleton INT NOT NULL PRIMARY KEY,
		authority_id VARCHAR(128) NOT NULL,
		incarnation CHAR(32) NOT NULL,
		catalog_digest CHAR(64) NOT NULL,
		election_generation BIGINT NOT NULL,
		active_writer_id CHAR(32) NOT NULL,
		committed_position BIGINT NOT NULL,
		acknowledged_position BIGINT NOT NULL,
		recoverable_scope_checkpoint BIGINT NOT NULL,
		state_hmac CHAR(64) NOT NULL,
		updated_at BIGINT NOT NULL
	)`
)

// RecoveryFenceV1 is the surviving external recovery and election fence record.
// Incarnation is the 32-hex continuity-verified authority lineage stored in
// NativeAnchor.AuthorityIncarnation and reported in NativeFactSource SQL cuts.
// ElectionGeneration is the strictly positive HA writer term/epoch; a normal
// failover bumps ElectionGeneration while preserving Incarnation after
// RecoverAtLeast proves RecoverableScopeCheckpoint >= MinAckPosition.
type RecoveryFenceV1 struct {
	AuthorityID                string `json:"authority_id"`
	Incarnation                string `json:"incarnation"`
	ElectionGeneration         uint64 `json:"election_generation"`
	MinAckPosition             uint64 `json:"min_ack_position"`
	RecoverableScopeCheckpoint uint64 `json:"recoverable_scope_checkpoint"`
	CatalogDigest              string `json:"catalog_digest"`
}

func (f RecoveryFenceV1) Validate(expectedCatalogDigest string) error {
	if !validText(f.AuthorityID, 128, 128) || !validHex(f.Incarnation, 32) || f.ElectionGeneration == 0 || !validHex(f.CatalogDigest, 64) {
		return fmt.Errorf("%w: invalid recovery fence fields", ErrUnavailable)
	}
	if expectedCatalogDigest != "" && f.CatalogDigest != expectedCatalogDigest {
		return fmt.Errorf("%w: recovery fence catalog digest mismatch", ErrUnavailable)
	}
	if f.RecoverableScopeCheckpoint < f.MinAckPosition {
		return fmt.Errorf("%w: recoverable scope checkpoint %d behind min_ack_position %d", ErrUnavailable, f.RecoverableScopeCheckpoint, f.MinAckPosition)
	}
	return nil
}

// ElectedAuthoritySession binds one RepeatableRead SQL transaction to the
// currently elected writer/session under a verified authority lineage.
type ElectedAuthoritySession struct {
	AuthorityID        string `json:"authority_id"`
	Incarnation        string `json:"incarnation"`
	ElectionGeneration uint64 `json:"election_generation"`
	Position           uint64 `json:"position"`
}

func (s ElectedAuthoritySession) Validate() error {
	if !validText(s.AuthorityID, 128, 128) || !validHex(s.Incarnation, 32) || s.ElectionGeneration == 0 {
		return fmt.Errorf("%w: invalid elected authority session", ErrUnavailable)
	}
	return nil
}

// ExternalAuthorityDriver is the concrete seam for external SQL writer election,
// session fencing, monotonic commit positions, and surviving recovery coverage.
// Neither local SQL writable flags (@@read_only / @@super_read_only) nor a
// counter stored in the same MySQL instance can implement this seam.
type ExternalAuthorityDriver interface {
	RecoverAtLeast(ctx context.Context, expectedCatalogDigest string) (RecoveryFenceV1, error)
	AcquireCurrent(ctx context.Context, tx *dbr.Tx) (ElectedAuthoritySession, error)
	AssertCurrent(ctx context.Context, tx *dbr.Tx, session ElectedAuthoritySession) error
	RecordAcknowledgedPosition(ctx context.Context, session ElectedAuthoritySession) error
}

// RejectUnfencedAuthorityMode rejects local SQL writable variables, same-DB
// counters, and unverified pool/lease substitutes that cannot establish
// FencedAuthority or RecoverAtLeast across failover and point-in-time restore.
func RejectUnfencedAuthorityMode(mode string) error {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	switch normalized {
	case AuthorityModeExternalFencedV1, AuthorityModeNativeSingleWriterV1:
		return nil
	case "", "none", "disabled":
		return fmt.Errorf("%w: fenced authority mode not configured", ErrUnavailable)
	case "sql_read_only_variables", "mysql_read_only", "super_read_only", "@@read_only", "@@super_read_only":
		return fmt.Errorf("%w: local SQL writable flags (%s) cannot substitute for FencedAuthority or RecoverAtLeast", ErrUnavailable, mode)
	case "same_db_counter", "local_sql_table", "same_mysql_counter":
		return fmt.Errorf("%w: same-DB counter (%s) rolls back with the restored database and cannot substitute for FencedAuthority or RecoverAtLeast", ErrUnavailable, mode)
	case "unverified_pool", "server_uuid", "timestamp", "cutover_floor", "credential_writer_lease", "session_rollout_floor":
		return fmt.Errorf("%w: unfenced authority substitute (%s) is not a valid FencedAuthority", ErrUnavailable, mode)
	default:
		return fmt.Errorf("%w: unsupported authority mode %q", ErrUnavailable, mode)
	}
}

// FencedAuthorityAdapter implements FencedAuthority over an ExternalAuthorityDriver.
type FencedAuthorityAdapter struct {
	driver                ExternalAuthorityDriver
	expectedCatalogDigest string

	mu        sync.RWMutex
	recovered bool
	fence     RecoveryFenceV1
}

func NewFencedAuthorityAdapter(ctx context.Context, driver ExternalAuthorityDriver, expectedCatalogDigest string) (*FencedAuthorityAdapter, error) {
	if driver == nil || !validHex(expectedCatalogDigest, 64) {
		return nil, fmt.Errorf("%w: missing external authority driver or catalog digest", ErrUnavailable)
	}
	adapter := &FencedAuthorityAdapter{
		driver:                driver,
		expectedCatalogDigest: expectedCatalogDigest,
	}
	if _, err := adapter.RecoverAtLeast(ctx); err != nil {
		return nil, err
	}
	return adapter, nil
}

func (a *FencedAuthorityAdapter) RecoverAtLeast(ctx context.Context) (RecoveryFenceV1, error) {
	if a == nil || a.driver == nil {
		return RecoveryFenceV1{}, ErrUnavailable
	}
	fence, err := a.driver.RecoverAtLeast(ctx, a.expectedCatalogDigest)
	if err != nil {
		return RecoveryFenceV1{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := fence.Validate(a.expectedCatalogDigest); err != nil {
		return RecoveryFenceV1{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.recovered {
		if fence.AuthorityID != a.fence.AuthorityID || fence.Incarnation != a.fence.Incarnation {
			return RecoveryFenceV1{}, fmt.Errorf("%w: discontinuous authority incarnation change requires explicit store reprovisioning", ErrUnavailable)
		}
		if fence.ElectionGeneration < a.fence.ElectionGeneration || fence.MinAckPosition < a.fence.MinAckPosition {
			return RecoveryFenceV1{}, fmt.Errorf("%w: authority recovery fence regressed", ErrUnavailable)
		}
	}
	a.fence = fence
	a.recovered = true
	return fence, nil
}

func (a *FencedAuthorityAdapter) Fence() (RecoveryFenceV1, bool) {
	if a == nil {
		return RecoveryFenceV1{}, false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.fence, a.recovered
}

func (a *FencedAuthorityAdapter) VerifySQLAuthorityCut(authorityID, incarnation, position string) error {
	if a == nil {
		return ErrUnavailable
	}
	pos, err := U64(position)
	if err != nil {
		return ErrUnavailable
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.recovered || authorityID != a.fence.AuthorityID || incarnation != a.fence.Incarnation || pos < a.fence.MinAckPosition {
		return ErrUnavailable
	}
	return nil
}

func (a *FencedAuthorityAdapter) Begin(ctx context.Context, tx *dbr.Tx) (AuthorityRead, error) {
	if a == nil || a.driver == nil || tx == nil {
		return nil, ErrUnavailable
	}
	a.mu.RLock()
	recovered := a.recovered
	a.mu.RUnlock()
	if !recovered {
		return nil, ErrUnavailable
	}
	session, err := a.driver.AcquireCurrent(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := session.Validate(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.recovered || session.AuthorityID != a.fence.AuthorityID || session.Incarnation != a.fence.Incarnation {
		return nil, ErrUnavailable
	}
	if session.ElectionGeneration < a.fence.ElectionGeneration || session.Position < a.fence.MinAckPosition {
		return nil, ErrUnavailable
	}
	if session.ElectionGeneration > a.fence.ElectionGeneration {
		a.fence.ElectionGeneration = session.ElectionGeneration
	}
	return &FencedAuthorityRead{
		adapter: a,
		tx:      tx,
		session: session,
	}, nil
}

// FencedAuthorityRead binds one transaction's authority read/write lease.
// Incarnation() returns the 32-hex continuity-verified authority lineage and
// remains distinct from ElectionGeneration().
type FencedAuthorityRead struct {
	adapter *FencedAuthorityAdapter
	tx      *dbr.Tx
	session ElectedAuthoritySession
}

func (r *FencedAuthorityRead) Incarnation() string {
	if r == nil {
		return ""
	}
	return r.session.Incarnation
}

func (r *FencedAuthorityRead) ElectionGeneration() uint64 {
	if r == nil {
		return 0
	}
	return r.session.ElectionGeneration
}

func (r *FencedAuthorityRead) AuthorityID() string {
	if r == nil {
		return ""
	}
	return r.session.AuthorityID
}

func (r *FencedAuthorityRead) Position() uint64 {
	if r == nil {
		return 0
	}
	return r.session.Position
}

func (r *FencedAuthorityRead) Session() ElectedAuthoritySession {
	if r == nil {
		return ElectedAuthoritySession{}
	}
	return r.session
}

func (r *FencedAuthorityRead) Validate(ctx context.Context) error {
	if r == nil || r.adapter == nil || r.tx == nil {
		return ErrUnavailable
	}
	r.adapter.mu.RLock()
	recovered := r.adapter.recovered
	fence := r.adapter.fence
	r.adapter.mu.RUnlock()
	if !recovered || r.session.AuthorityID != fence.AuthorityID || r.session.Incarnation != fence.Incarnation || r.session.ElectionGeneration < fence.ElectionGeneration || r.session.Position < fence.MinAckPosition {
		return ErrUnavailable
	}
	if err := r.adapter.driver.AssertCurrent(ctx, r.tx, r.session); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

func (r *FencedAuthorityRead) Acknowledge(ctx context.Context) error {
	if r == nil || r.adapter == nil {
		return ErrReconcile
	}
	if err := r.adapter.driver.RecordAcknowledgedPosition(ctx, r.session); err != nil {
		return fmt.Errorf("%w: %v", ErrReconcile, err)
	}
	r.adapter.mu.Lock()
	defer r.adapter.mu.Unlock()
	if r.session.Position > r.adapter.fence.MinAckPosition {
		r.adapter.fence.MinAckPosition = r.session.Position
	}
	if r.session.Position > r.adapter.fence.RecoverableScopeCheckpoint {
		r.adapter.fence.RecoverableScopeCheckpoint = r.session.Position
	}
	if r.session.ElectionGeneration > r.adapter.fence.ElectionGeneration {
		r.adapter.fence.ElectionGeneration = r.session.ElectionGeneration
	}
	return nil
}

// NativeSingleWriterLineageConfig configures the bounded single-writer
// continuous-lineage authority driver (AuthorityModeNativeSingleWriterV1).
// It enforces uninterrupted durable store lineage across normal process
// restarts by cross-verifying an HMAC-authenticated host state file
// (StatePath, mode 0600, regular file) against the durable SQL lineage table
// (bot_permission_authority_lineage) and all existing bot_permission_scope
// anchors. It makes no multi-writer HA failover or stale-restore claim and
// refuses any missing, corrupt, key-mismatched, incarnation-mismatched, or
// regressed state.
type NativeSingleWriterLineageConfig struct {
	Session       *dbr.Session
	Origin        string
	AuthorityID   string
	Incarnation   string
	CatalogDigest string
	StatePath     string
	Key           []byte
	Provision     bool
	testNoLocks   bool
}

type nativeAuthorityFileState struct {
	SchemaVersion              int    `json:"schema_version"`
	AuthorityID                string `json:"authority_id"`
	Incarnation                string `json:"incarnation"`
	CatalogDigest              string `json:"catalog_digest"`
	ElectionGeneration         uint64 `json:"election_generation"`
	ActiveWriterID             string `json:"active_writer_id"`
	MinAckPosition             uint64 `json:"min_ack_position"`
	RecoverableScopeCheckpoint uint64 `json:"recoverable_scope_checkpoint"`
	StateHMAC                  string `json:"state_hmac"`
}

type nativeAuthoritySQLRow struct {
	AuthorityID                string
	Incarnation                string
	CatalogDigest              string
	ElectionGeneration         uint64
	ActiveWriterID             string
	CommittedPosition          uint64
	AcknowledgedPosition       uint64
	RecoverableScopeCheckpoint uint64
	StateHMAC                  string
}

type NativeSingleWriterLineageDriver struct {
	session       *dbr.Session
	origin        string
	authorityID   string
	incarnation   string
	catalogDigest string
	statePath     string
	key           []byte
	provision     bool
	testNoLocks   bool

	mu                 sync.Mutex
	failed             bool
	activeWriterID     string
	electionGeneration uint64
	minAckPosition     uint64
	nextPos            uint64
	scopeVerified      bool
}

func validNativeAuthorityID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func NewNativeSingleWriterLineageDriver(cfg NativeSingleWriterLineageConfig) (*NativeSingleWriterLineageDriver, error) {
	if cfg.Session == nil {
		return nil, fmt.Errorf("%w: native single-writer authority requires an initialized SQL session", ErrUnavailable)
	}
	authorityID := strings.TrimSpace(cfg.AuthorityID)
	if authorityID == "" {
		authorityID = "sql-native-writer"
	}
	if !validNativeAuthorityID(authorityID) {
		return nil, fmt.Errorf("%w: invalid native authority_id %q", ErrUnavailable, authorityID)
	}
	incarnation := strings.TrimSpace(cfg.Incarnation)
	if !validHex(incarnation, 32) {
		return nil, fmt.Errorf("%w: native single-writer authority requires an explicit 32-hex incarnation", ErrUnavailable)
	}
	catalogDigest := strings.TrimSpace(cfg.CatalogDigest)
	if !validHex(catalogDigest, 64) {
		return nil, fmt.Errorf("%w: native single-writer authority requires a 64-hex catalog digest", ErrUnavailable)
	}
	statePath := strings.TrimSpace(cfg.StatePath)
	if statePath == "" {
		return nil, fmt.Errorf("%w: native single-writer authority requires a durable host state path", ErrUnavailable)
	}
	if len(cfg.Key) < 32 {
		return nil, fmt.Errorf("%w: native single-writer authority requires a >=32-byte HMAC key", ErrUnavailable)
	}
	return &NativeSingleWriterLineageDriver{
		session:       cfg.Session,
		origin:        strings.TrimSpace(cfg.Origin),
		authorityID:   authorityID,
		incarnation:   incarnation,
		catalogDigest: catalogDigest,
		statePath:     statePath,
		key:           append([]byte(nil), cfg.Key...),
		provision:     cfg.Provision,
		testNoLocks:   cfg.testNoLocks,
	}, nil
}

func (d *NativeSingleWriterLineageDriver) lockSuffix(forUpdate bool) string {
	if d.testNoLocks {
		return ""
	}
	if forUpdate {
		return " FOR UPDATE NOWAIT"
	}
	return " FOR SHARE NOWAIT"
}

func (d *NativeSingleWriterLineageDriver) computeMAC(domain string, parts ...string) string {
	mac := hmac.New(sha256.New, d.key)
	mac.Write([]byte(strconv.Itoa(len(domain))))
	mac.Write([]byte{':'})
	mac.Write([]byte(domain))
	for _, p := range parts {
		mac.Write([]byte{'|'})
		mac.Write([]byte(strconv.Itoa(len(p))))
		mac.Write([]byte{':'})
		mac.Write([]byte(p))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func (d *NativeSingleWriterLineageDriver) fileStateMAC(s nativeAuthorityFileState) string {
	return d.computeMAC(
		"native_authority_file_v1",
		strconv.Itoa(s.SchemaVersion),
		s.AuthorityID,
		s.Incarnation,
		s.CatalogDigest,
		strconv.FormatUint(s.ElectionGeneration, 10),
		s.ActiveWriterID,
		strconv.FormatUint(s.MinAckPosition, 10),
		strconv.FormatUint(s.RecoverableScopeCheckpoint, 10),
	)
}

func (d *NativeSingleWriterLineageDriver) sqlStateMAC(r nativeAuthoritySQLRow) string {
	return d.computeMAC(
		"native_authority_sql_v1",
		r.AuthorityID,
		r.Incarnation,
		r.CatalogDigest,
		strconv.FormatUint(r.ElectionGeneration, 10),
		r.ActiveWriterID,
		strconv.FormatUint(r.CommittedPosition, 10),
		strconv.FormatUint(r.AcknowledgedPosition, 10),
		strconv.FormatUint(r.RecoverableScopeCheckpoint, 10),
	)
}

func (d *NativeSingleWriterLineageDriver) readHostState() (nativeAuthorityFileState, bool, error) {
	info, err := os.Lstat(d.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nativeAuthorityFileState{}, false, nil
		}
		return nativeAuthorityFileState{}, false, fmt.Errorf("%w: stat authority state file: %v", ErrUnavailable, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nativeAuthorityFileState{}, true, fmt.Errorf("%w: authority state path must be a regular file", ErrUnavailable)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nativeAuthorityFileState{}, true, fmt.Errorf("%w: authority state file permissions must not grant group/other access", ErrUnavailable)
	}
	if info.Size() <= 0 || info.Size() > 16384 {
		return nativeAuthorityFileState{}, true, fmt.Errorf("%w: authority state file size out of bounds", ErrUnavailable)
	}
	raw, err := os.ReadFile(d.statePath)
	if err != nil {
		return nativeAuthorityFileState{}, true, fmt.Errorf("%w: read authority state file: %v", ErrUnavailable, err)
	}
	var st nativeAuthorityFileState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nativeAuthorityFileState{}, true, fmt.Errorf("%w: invalid authority state JSON: %v", ErrUnavailable, err)
	}
	if st.SchemaVersion != 1 || !validNativeAuthorityID(st.AuthorityID) || !validHex(st.Incarnation, 32) || !validHex(st.CatalogDigest, 64) || st.ElectionGeneration == 0 || !validHex(st.ActiveWriterID, 32) || st.MinAckPosition == 0 || st.RecoverableScopeCheckpoint < st.MinAckPosition || !validHex(st.StateHMAC, 64) {
		return nativeAuthorityFileState{}, true, fmt.Errorf("%w: invalid authority state fields", ErrUnavailable)
	}
	expectedMAC := d.fileStateMAC(st)
	if !hmac.Equal([]byte(st.StateHMAC), []byte(expectedMAC)) {
		return nativeAuthorityFileState{}, true, fmt.Errorf("%w: authority state HMAC verification failed", ErrUnavailable)
	}
	if st.AuthorityID != d.authorityID || st.Incarnation != d.incarnation || st.CatalogDigest != d.catalogDigest {
		return nativeAuthorityFileState{}, true, fmt.Errorf("%w: authority state identity or catalog digest mismatch", ErrUnavailable)
	}
	return st, true, nil
}

func (d *NativeSingleWriterLineageDriver) writeHostState(st nativeAuthorityFileState) error {
	st.SchemaVersion = 1
	st.StateHMAC = d.fileStateMAC(st)
	if info, err := os.Lstat(d.statePath); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: authority state path is not a regular file", ErrUnavailable)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("%w: stat authority state path: %v", ErrUnavailable, err)
	}
	dir := filepath.Dir(d.statePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: prepare authority state dir: %v", ErrUnavailable, err)
	}
	encoded, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("%w: marshal authority state: %v", ErrUnavailable, err)
	}
	tmp, err := os.CreateTemp(dir, ".authority-state-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: create temp authority state file: %v", ErrUnavailable, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("%w: chmod temp authority state file: %v", ErrUnavailable, err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("%w: write temp authority state file: %v", ErrUnavailable, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("%w: sync temp authority state file: %v", ErrUnavailable, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("%w: close temp authority state file: %v", ErrUnavailable, err)
	}
	if err := os.Rename(tmpName, d.statePath); err != nil {
		cleanup()
		return fmt.Errorf("%w: rename authority state file: %v", ErrUnavailable, err)
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

func isMissingTableError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such table") || strings.Contains(msg, "doesn't exist") || strings.Contains(msg, "error 1146")
}

func (d *NativeSingleWriterLineageDriver) readSQLRow(ctx context.Context, runner interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, forUpdate bool) (nativeAuthoritySQLRow, bool, error) {
	var r nativeAuthoritySQLRow
	var gen, committed, acked, checkpoint int64
	q := `SELECT authority_id,incarnation,catalog_digest,election_generation,active_writer_id,committed_position,acknowledged_position,recoverable_scope_checkpoint,state_hmac FROM ` + NativeAuthorityLineageTable + ` WHERE singleton=1` + d.lockSuffix(forUpdate)
	qCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := runner.QueryRowContext(qCtx, q).Scan(
		&r.AuthorityID,
		&r.Incarnation,
		&r.CatalogDigest,
		&gen,
		&r.ActiveWriterID,
		&committed,
		&acked,
		&checkpoint,
		&r.StateHMAC,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMissingTableError(err) {
			return nativeAuthoritySQLRow{}, false, nil
		}
		return nativeAuthoritySQLRow{}, false, fmt.Errorf("%w: read SQL authority lineage: %v", ErrUnavailable, err)
	}
	if gen <= 0 || committed <= 0 || acked <= 0 || checkpoint <= 0 {
		return nativeAuthoritySQLRow{}, true, fmt.Errorf("%w: non-positive SQL authority lineage counters", ErrUnavailable)
	}
	r.ElectionGeneration = uint64(gen)
	r.CommittedPosition = uint64(committed)
	r.AcknowledgedPosition = uint64(acked)
	r.RecoverableScopeCheckpoint = uint64(checkpoint)
	if !validNativeAuthorityID(r.AuthorityID) || !validHex(r.Incarnation, 32) || !validHex(r.CatalogDigest, 64) || !validHex(r.ActiveWriterID, 32) || r.CommittedPosition < r.AcknowledgedPosition || r.RecoverableScopeCheckpoint < r.AcknowledgedPosition || !validHex(r.StateHMAC, 64) {
		return nativeAuthoritySQLRow{}, true, fmt.Errorf("%w: invalid SQL authority lineage fields", ErrUnavailable)
	}
	expectedMAC := d.sqlStateMAC(r)
	if !hmac.Equal([]byte(r.StateHMAC), []byte(expectedMAC)) {
		return nativeAuthoritySQLRow{}, true, fmt.Errorf("%w: SQL authority lineage HMAC verification failed", ErrUnavailable)
	}
	if r.AuthorityID != d.authorityID || r.Incarnation != d.incarnation || r.CatalogDigest != d.catalogDigest {
		return nativeAuthoritySQLRow{}, true, fmt.Errorf("%w: SQL authority lineage identity or catalog digest mismatch", ErrUnavailable)
	}
	return r, true, nil
}

func (d *NativeSingleWriterLineageDriver) verifyScopeTableInTx(ctx context.Context, tx *dbr.Tx) (int, bool, error) {
	q := `SELECT bot_uid,space_id,scope_incarnation,revision,context_epoch,schema_version,catalog_version,catalog_digest,bundle_json,bundle_digest,native_anchor_json,native_anchor_digest,retired FROM bot_permission_scope` + d.lockSuffix(false)
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := tx.QueryContext(qCtx, q)
	if err != nil {
		if isMissingTableError(err) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("%w: query bot_permission_scope during lineage check: %v", ErrUnavailable, err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var botUID, spaceID, rev, epoch, cat string
		var nonce, catDigest, bundle, bd, anchorRaw, ad []byte
		var version, retired int
		if err := rows.Scan(&botUID, &spaceID, &nonce, &rev, &epoch, &version, &cat, &catDigest, &bundle, &bd, &anchorRaw, &ad, &retired); err != nil {
			return 0, true, fmt.Errorf("%w: scan bot_permission_scope row: %v", ErrUnavailable, err)
		}
		if len(nonce) != 16 || len(catDigest) != 32 || len(bd) != 32 || len(ad) != 32 || (retired != 0 && retired != 1) {
			return 0, true, fmt.Errorf("%w: malformed bot_permission_scope binary columns", ErrUnavailable)
		}
		p, err := ParseBundle(bytes.NewReader(bundle))
		if err != nil || p.Key.BotUID != botUID || p.Key.SpaceID != spaceID || (d.origin != "" && p.Key.Origin != d.origin) || p.Incarnation != hex.EncodeToString(nonce) || p.Revision != rev || p.ContextEpoch != epoch || p.SchemaVersion != version || p.CatalogVersion != cat || p.CatalogDigest != hex.EncodeToString(catDigest) || p.Digest != hex.EncodeToString(bd) {
			return 0, true, fmt.Errorf("%w: bot_permission_scope bundle digest or identity mismatch", ErrUnavailable)
		}
		v, err := decodeStrict(bytes.NewReader(anchorRaw), 4096)
		if err != nil {
			return 0, true, fmt.Errorf("%w: invalid bot_permission_scope native_anchor_json", ErrUnavailable)
		}
		canonicalAnchor := canonical(v)
		if hash(canonicalAnchor) != hex.EncodeToString(ad) {
			return 0, true, fmt.Errorf("%w: bot_permission_scope native_anchor_digest mismatch", ErrUnavailable)
		}
		var anchor NativeAnchor
		if err := json.Unmarshal(canonicalAnchor, &anchor); err != nil || !validAnchor(anchor) || anchor.AuthorityIncarnation != d.incarnation {
			return 0, true, fmt.Errorf("%w: bot_permission_scope authority_incarnation mismatch", ErrUnavailable)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, true, fmt.Errorf("%w: iterate bot_permission_scope: %v", ErrUnavailable, err)
	}
	return count, true, nil
}

func (d *NativeSingleWriterLineageDriver) RecoverAtLeast(ctx context.Context, expectedCatalogDigest string) (RecoveryFenceV1, error) {
	if d == nil || d.session == nil {
		return RecoveryFenceV1{}, ErrUnavailable
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed {
		return RecoveryFenceV1{}, ErrUnavailable
	}
	if expectedCatalogDigest != "" && expectedCatalogDigest != d.catalogDigest {
		return RecoveryFenceV1{}, fmt.Errorf("%w: expected catalog digest mismatch", ErrUnavailable)
	}

	hostState, hostExists, err := d.readHostState()
	if err != nil {
		return RecoveryFenceV1{}, err
	}

	if d.provision && !hostExists {
		if _, err := d.session.ExecContext(ctx, NativeAuthorityLineageDDL); err != nil {
			return RecoveryFenceV1{}, fmt.Errorf("%w: ensure %s table: %v", ErrUnavailable, NativeAuthorityLineageTable, err)
		}
	}

	sess := *d.session
	sess.EventReceiver = &dbr.NullEventReceiver{}
	tx, err := sess.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return RecoveryFenceV1{}, fmt.Errorf("%w: begin authority recovery tx: %v", ErrUnavailable, err)
	}
	defer tx.RollbackUnlessCommitted()

	sqlRow, sqlExists, err := d.readSQLRow(ctx, tx, true)
	if err != nil {
		return RecoveryFenceV1{}, err
	}

	scopeCount, scopeTableExists, err := d.verifyScopeTableInTx(ctx, tx)
	if err != nil {
		return RecoveryFenceV1{}, err
	}
	if !scopeTableExists && (!d.provision || hostExists || sqlExists) {
		return RecoveryFenceV1{}, fmt.Errorf("%w: bot_permission_scope table missing", ErrUnavailable)
	}

	switch {
	case !hostExists && !sqlExists:
		if !d.provision {
			return RecoveryFenceV1{}, fmt.Errorf("%w: native authority lineage state missing and provisioning is disabled", ErrUnavailable)
		}
		if scopeCount > 0 {
			return RecoveryFenceV1{}, fmt.Errorf("%w: native authority lineage state missing while bot_permission_scope already has %d row(s)", ErrUnavailable, scopeCount)
		}
		writerID, err := randomHex32()
		if err != nil {
			return RecoveryFenceV1{}, err
		}
		row := nativeAuthoritySQLRow{
			AuthorityID:                d.authorityID,
			Incarnation:                d.incarnation,
			CatalogDigest:              d.catalogDigest,
			ElectionGeneration:         1,
			ActiveWriterID:             writerID,
			CommittedPosition:          1,
			AcknowledgedPosition:       1,
			RecoverableScopeCheckpoint: 1,
		}
		row.StateHMAC = d.sqlStateMAC(row)
		now := time.Now().UTC().UnixNano()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO `+NativeAuthorityLineageTable+` (singleton,authority_id,incarnation,catalog_digest,election_generation,active_writer_id,committed_position,acknowledged_position,recoverable_scope_checkpoint,state_hmac,updated_at) VALUES (1,?,?,?,?,?,?,?,?,?,?)`,
			row.AuthorityID, row.Incarnation, row.CatalogDigest, int64(row.ElectionGeneration), row.ActiveWriterID, int64(row.CommittedPosition), int64(row.AcknowledgedPosition), int64(row.RecoverableScopeCheckpoint), row.StateHMAC, now,
		); err != nil {
			return RecoveryFenceV1{}, fmt.Errorf("%w: insert initial SQL authority lineage: %v", ErrUnavailable, err)
		}
		if err := tx.Commit(); err != nil {
			return RecoveryFenceV1{}, fmt.Errorf("%w: commit initial SQL authority lineage: %v", ErrUnavailable, err)
		}
		if err := d.writeHostState(nativeAuthorityFileState{
			SchemaVersion:              1,
			AuthorityID:                d.authorityID,
			Incarnation:                d.incarnation,
			CatalogDigest:              d.catalogDigest,
			ElectionGeneration:         1,
			ActiveWriterID:             writerID,
			MinAckPosition:             1,
			RecoverableScopeCheckpoint: 1,
		}); err != nil {
			d.failed = true
			return RecoveryFenceV1{}, err
		}
		d.activeWriterID = writerID
		d.electionGeneration = 1
		d.minAckPosition = 1
		d.nextPos = 1
		d.scopeVerified = scopeTableExists
		return RecoveryFenceV1{
			AuthorityID:                d.authorityID,
			Incarnation:                d.incarnation,
			ElectionGeneration:         1,
			MinAckPosition:             1,
			RecoverableScopeCheckpoint: 1,
			CatalogDigest:              d.catalogDigest,
		}, nil

	case hostExists && !sqlExists:
		return RecoveryFenceV1{}, fmt.Errorf("%w: SQL authority lineage missing while host authority state exists; database loss or unrecovered restore detected", ErrUnavailable)

	case !hostExists && sqlExists:
		return RecoveryFenceV1{}, fmt.Errorf("%w: host authority state file missing while SQL authority lineage exists; authority journal loss detected", ErrUnavailable)

	default:
		if sqlRow.ElectionGeneration < hostState.ElectionGeneration ||
			sqlRow.CommittedPosition < hostState.MinAckPosition ||
			sqlRow.AcknowledgedPosition < hostState.MinAckPosition ||
			sqlRow.RecoverableScopeCheckpoint < hostState.MinAckPosition {
			return RecoveryFenceV1{}, fmt.Errorf("%w: SQL authority lineage regressed behind host authority checkpoint", ErrUnavailable)
		}
		if sqlRow.AcknowledgedPosition < uint64(scopeCount)+1 {
			return RecoveryFenceV1{}, fmt.Errorf("%w: SQL authority acknowledged position (%d) behind scope count floor (%d)", ErrUnavailable, sqlRow.AcknowledgedPosition, scopeCount+1)
		}
		if d.activeWriterID != "" && sqlRow.ActiveWriterID == d.activeWriterID && hostState.ActiveWriterID == d.activeWriterID && sqlRow.ElectionGeneration == d.electionGeneration {
			if !scopeTableExists {
				return RecoveryFenceV1{}, fmt.Errorf("%w: bot_permission_scope table missing after setup", ErrUnavailable)
			}
			if err := tx.Commit(); err != nil {
				return RecoveryFenceV1{}, fmt.Errorf("%w: commit authority verification tx: %v", ErrUnavailable, err)
			}
			d.scopeVerified = true
			return RecoveryFenceV1{
				AuthorityID:                d.authorityID,
				Incarnation:                d.incarnation,
				ElectionGeneration:         d.electionGeneration,
				MinAckPosition:             d.minAckPosition,
				RecoverableScopeCheckpoint: d.minAckPosition,
				CatalogDigest:              d.catalogDigest,
			}, nil
		}

		writerID, err := randomHex32()
		if err != nil {
			return RecoveryFenceV1{}, err
		}
		nextGen := sqlRow.ElectionGeneration
		if hostState.ElectionGeneration > nextGen {
			nextGen = hostState.ElectionGeneration
		}
		nextGen++
		pos := sqlRow.CommittedPosition
		if sqlRow.AcknowledgedPosition > pos {
			pos = sqlRow.AcknowledgedPosition
		}
		if hostState.MinAckPosition > pos {
			pos = hostState.MinAckPosition
		}
		updated := nativeAuthoritySQLRow{
			AuthorityID:                d.authorityID,
			Incarnation:                d.incarnation,
			CatalogDigest:              d.catalogDigest,
			ElectionGeneration:         nextGen,
			ActiveWriterID:             writerID,
			CommittedPosition:          pos,
			AcknowledgedPosition:       pos,
			RecoverableScopeCheckpoint: pos,
		}
		updated.StateHMAC = d.sqlStateMAC(updated)
		now := time.Now().UTC().UnixNano()
		res, err := tx.ExecContext(ctx,
			`UPDATE `+NativeAuthorityLineageTable+` SET election_generation=?,active_writer_id=?,committed_position=?,acknowledged_position=?,recoverable_scope_checkpoint=?,state_hmac=?,updated_at=? WHERE singleton=1 AND authority_id=? AND incarnation=? AND election_generation=? AND state_hmac=?`,
			int64(updated.ElectionGeneration), updated.ActiveWriterID, int64(updated.CommittedPosition), int64(updated.AcknowledgedPosition), int64(updated.RecoverableScopeCheckpoint), updated.StateHMAC, now,
			d.authorityID, d.incarnation, int64(sqlRow.ElectionGeneration), sqlRow.StateHMAC,
		)
		if err != nil {
			return RecoveryFenceV1{}, fmt.Errorf("%w: update SQL authority lineage on restart: %v", ErrUnavailable, err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return RecoveryFenceV1{}, fmt.Errorf("%w: SQL authority lineage CAS failed on restart", ErrUnavailable)
		}
		if err := tx.Commit(); err != nil {
			return RecoveryFenceV1{}, fmt.Errorf("%w: commit SQL authority lineage on restart: %v", ErrUnavailable, err)
		}
		if err := d.writeHostState(nativeAuthorityFileState{
			SchemaVersion:              1,
			AuthorityID:                d.authorityID,
			Incarnation:                d.incarnation,
			CatalogDigest:              d.catalogDigest,
			ElectionGeneration:         nextGen,
			ActiveWriterID:             writerID,
			MinAckPosition:             pos,
			RecoverableScopeCheckpoint: pos,
		}); err != nil {
			d.failed = true
			return RecoveryFenceV1{}, err
		}
		d.activeWriterID = writerID
		d.electionGeneration = nextGen
		d.minAckPosition = pos
		d.nextPos = pos
		d.scopeVerified = scopeTableExists
		return RecoveryFenceV1{
			AuthorityID:                d.authorityID,
			Incarnation:                d.incarnation,
			ElectionGeneration:         nextGen,
			MinAckPosition:             pos,
			RecoverableScopeCheckpoint: pos,
			CatalogDigest:              d.catalogDigest,
		}, nil
	}
}

func (d *NativeSingleWriterLineageDriver) AcquireCurrent(ctx context.Context, tx *dbr.Tx) (ElectedAuthoritySession, error) {
	if d == nil || tx == nil {
		return ElectedAuthoritySession{}, ErrUnavailable
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed || d.activeWriterID == "" || d.electionGeneration == 0 {
		return ElectedAuthoritySession{}, ErrUnavailable
	}
	hostState, hostExists, err := d.readHostState()
	if err != nil || !hostExists {
		d.failed = true
		return ElectedAuthoritySession{}, fmt.Errorf("%w: host authority state unavailable during AcquireCurrent", ErrUnavailable)
	}
	if hostState.ActiveWriterID != d.activeWriterID || hostState.ElectionGeneration != d.electionGeneration || hostState.MinAckPosition < d.minAckPosition {
		d.failed = true
		return ElectedAuthoritySession{}, fmt.Errorf("%w: host authority state writer lease superseded or regressed", ErrUnavailable)
	}
	sqlRow, sqlExists, err := d.readSQLRow(ctx, tx, false)
	if err != nil || !sqlExists {
		d.failed = true
		return ElectedAuthoritySession{}, fmt.Errorf("%w: SQL authority lineage unavailable during AcquireCurrent", ErrUnavailable)
	}
	if sqlRow.ActiveWriterID != d.activeWriterID || sqlRow.ElectionGeneration != d.electionGeneration || sqlRow.AcknowledgedPosition < hostState.MinAckPosition {
		d.failed = true
		return ElectedAuthoritySession{}, fmt.Errorf("%w: SQL authority lineage writer lease superseded or regressed", ErrUnavailable)
	}
	if !d.scopeVerified {
		_, scopeTableExists, err := d.verifyScopeTableInTx(ctx, tx)
		if err != nil || !scopeTableExists {
			return ElectedAuthoritySession{}, fmt.Errorf("%w: bot_permission_scope verification failed during AcquireCurrent", ErrUnavailable)
		}
		d.scopeVerified = true
	}
	if d.nextPos < sqlRow.CommittedPosition {
		d.nextPos = sqlRow.CommittedPosition
	}
	if d.nextPos < hostState.MinAckPosition {
		d.nextPos = hostState.MinAckPosition
	}
	d.nextPos++
	return ElectedAuthoritySession{
		AuthorityID:        d.authorityID,
		Incarnation:        d.incarnation,
		ElectionGeneration: d.electionGeneration,
		Position:           d.nextPos,
	}, nil
}

func (d *NativeSingleWriterLineageDriver) AssertCurrent(ctx context.Context, tx *dbr.Tx, session ElectedAuthoritySession) error {
	if d == nil || tx == nil {
		return ErrUnavailable
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed || d.activeWriterID == "" || session.AuthorityID != d.authorityID || session.Incarnation != d.incarnation || session.ElectionGeneration != d.electionGeneration || session.Position < d.minAckPosition {
		return ErrUnavailable
	}
	hostState, hostExists, err := d.readHostState()
	if err != nil || !hostExists || hostState.ActiveWriterID != d.activeWriterID || hostState.ElectionGeneration != d.electionGeneration || hostState.MinAckPosition < d.minAckPosition {
		d.failed = true
		return ErrUnavailable
	}
	sqlRow, sqlExists, err := d.readSQLRow(ctx, tx, false)
	if err != nil || !sqlExists || sqlRow.ActiveWriterID != d.activeWriterID || sqlRow.ElectionGeneration != d.electionGeneration || sqlRow.AcknowledgedPosition < hostState.MinAckPosition {
		d.failed = true
		return ErrUnavailable
	}
	return nil
}

func (d *NativeSingleWriterLineageDriver) RecordAcknowledgedPosition(ctx context.Context, session ElectedAuthoritySession) error {
	if d == nil || d.session == nil {
		return ErrReconcile
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed || d.activeWriterID == "" || session.AuthorityID != d.authorityID || session.Incarnation != d.incarnation || session.ElectionGeneration != d.electionGeneration {
		return ErrReconcile
	}
	hostState, hostExists, err := d.readHostState()
	if err != nil || !hostExists || hostState.ActiveWriterID != d.activeWriterID || hostState.ElectionGeneration != d.electionGeneration {
		d.failed = true
		return ErrReconcile
	}
	sqlRow, sqlExists, err := d.readSQLRow(ctx, d.session, false)
	if err != nil || !sqlExists || sqlRow.ActiveWriterID != d.activeWriterID || sqlRow.ElectionGeneration != d.electionGeneration || sqlRow.AcknowledgedPosition < hostState.MinAckPosition {
		d.failed = true
		return ErrReconcile
	}
	nextAck := sqlRow.AcknowledgedPosition
	if hostState.MinAckPosition > nextAck {
		nextAck = hostState.MinAckPosition
	}
	if session.Position > nextAck {
		nextAck = session.Position
	}
	nextCommitted := sqlRow.CommittedPosition
	if nextAck > nextCommitted {
		nextCommitted = nextAck
	}
	if d.nextPos > nextCommitted {
		nextCommitted = d.nextPos
	}
	updated := nativeAuthoritySQLRow{
		AuthorityID:                d.authorityID,
		Incarnation:                d.incarnation,
		CatalogDigest:              d.catalogDigest,
		ElectionGeneration:         d.electionGeneration,
		ActiveWriterID:             d.activeWriterID,
		CommittedPosition:          nextCommitted,
		AcknowledgedPosition:       nextAck,
		RecoverableScopeCheckpoint: nextAck,
	}
	updated.StateHMAC = d.sqlStateMAC(updated)
	now := time.Now().UTC().UnixNano()
	qCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	res, err := d.session.ExecContext(qCtx,
		`UPDATE `+NativeAuthorityLineageTable+` SET committed_position=?,acknowledged_position=?,recoverable_scope_checkpoint=?,state_hmac=?,updated_at=? WHERE singleton=1 AND authority_id=? AND incarnation=? AND active_writer_id=? AND election_generation=? AND state_hmac=?`,
		int64(updated.CommittedPosition), int64(updated.AcknowledgedPosition), int64(updated.RecoverableScopeCheckpoint), updated.StateHMAC, now,
		d.authorityID, d.incarnation, d.activeWriterID, int64(d.electionGeneration), sqlRow.StateHMAC,
	)
	if err != nil {
		d.failed = true
		return ErrReconcile
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		d.failed = true
		return ErrReconcile
	}
	if err := d.writeHostState(nativeAuthorityFileState{
		SchemaVersion:              1,
		AuthorityID:                d.authorityID,
		Incarnation:                d.incarnation,
		CatalogDigest:              d.catalogDigest,
		ElectionGeneration:         d.electionGeneration,
		ActiveWriterID:             d.activeWriterID,
		MinAckPosition:             nextAck,
		RecoverableScopeCheckpoint: nextAck,
	}); err != nil {
		d.failed = true
		return ErrReconcile
	}
	d.minAckPosition = nextAck
	return nil
}
