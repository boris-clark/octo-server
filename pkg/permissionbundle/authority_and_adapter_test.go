package permissionbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-lib/config"
	"github.com/Mininglamp-OSS/octo-lib/pkg/wkhttp"
	"github.com/Mininglamp-OSS/octo-server/pkg/i18n"
	"github.com/gocraft/dbr/v2"
	"github.com/stretchr/testify/require"
)

type syntheticExternalAuthorityDriver struct {
	mu          sync.Mutex
	authorityID string
	incarnation string
	generation  uint64
	minAckPos   uint64
	checkpoint  uint64
	nextPos     uint64
	catalogHash string
	assertErr   error
	ackErr      error
}

func newSyntheticExternalAuthorityDriver(catalogDigest string) *syntheticExternalAuthorityDriver {
	return &syntheticExternalAuthorityDriver{
		authorityID: "sql-ha-primary",
		incarnation: strings.Repeat("a", 32),
		generation:  1,
		minAckPos:   10,
		checkpoint:  10,
		nextPos:     10,
		catalogHash: catalogDigest,
	}
}

func (d *syntheticExternalAuthorityDriver) RecoverAtLeast(_ context.Context, expectedCatalogDigest string) (RecoveryFenceV1, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cat := d.catalogHash
	if cat == "" {
		cat = expectedCatalogDigest
	}
	return RecoveryFenceV1{
		AuthorityID:                d.authorityID,
		Incarnation:                d.incarnation,
		ElectionGeneration:         d.generation,
		MinAckPosition:             d.minAckPos,
		RecoverableScopeCheckpoint: d.checkpoint,
		CatalogDigest:              cat,
	}, nil
}

func (d *syntheticExternalAuthorityDriver) AcquireCurrent(_ context.Context, _ *dbr.Tx) (ElectedAuthoritySession, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nextPos++
	return ElectedAuthoritySession{
		AuthorityID:        d.authorityID,
		Incarnation:        d.incarnation,
		ElectionGeneration: d.generation,
		Position:           d.nextPos,
	}, nil
}

func (d *syntheticExternalAuthorityDriver) AssertCurrent(_ context.Context, _ *dbr.Tx, session ElectedAuthoritySession) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.assertErr != nil {
		return d.assertErr
	}
	if session.AuthorityID != d.authorityID || session.Incarnation != d.incarnation || session.ElectionGeneration != d.generation {
		return ErrUnavailable
	}
	return nil
}

func (d *syntheticExternalAuthorityDriver) RecordAcknowledgedPosition(_ context.Context, session ElectedAuthoritySession) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ackErr != nil {
		return d.ackErr
	}
	if session.Position > d.minAckPos {
		d.minAckPos = session.Position
	}
	if session.Position > d.checkpoint {
		d.checkpoint = session.Position
	}
	return nil
}

func TestFencedAuthorityIncarnationLineageFailoverAndRejectUnfencedSubstitutes(t *testing.T) {
	ctx := t.Context()
	for _, badMode := range []string{
		"",
		"none",
		"sql_read_only_variables",
		"mysql_read_only",
		"super_read_only",
		"@@read_only",
		"@@super_read_only",
		"same_db_counter",
		"local_sql_table",
		"unverified_pool",
		"server_uuid",
		"timestamp",
		"cutover_floor",
		"credential_writer_lease",
		"session_rollout_floor",
	} {
		err := RejectUnfencedAuthorityMode(badMode)
		require.ErrorIs(t, err, ErrUnavailable, "mode=%s", badMode)
	}
	require.NoError(t, RejectUnfencedAuthorityMode(AuthorityModeExternalFencedV1))

	driver := newSyntheticExternalAuthorityDriver(fixturePin.Digest)
	adapter, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "fenced-authority.sqlite")
	s := fixtureStore(t, path)
	s.Authority = adapter
	seed(t, s)

	// Initial read under election_generation=1 succeeds and preserves 32-hex incarnation.
	initial, err := s.Get(ctx, fixtureKey, "owner")
	require.NoError(t, err)
	require.Equal(t, "0", initial.Bundle.Revision)

	// Prepare -> CAS Mutate -> Owner GET readback under generation 1.
	prepReq, _ := json.Marshal(Preparation{Key: fixtureKey, Expected: initial.Bundle.Expected(), PeerUIDs: []string{"peer", "departed"}})
	prepared, err := s.Prepare(ctx, fixtureKey, "owner", bytes.NewReader(prepReq))
	require.NoError(t, err)
	require.Len(t, prepared.References, 2)

	denyRule := fixtureRule("deny")
	denyRule["caller"] = map[string]any{"kind": "uids", "uids": []any{"departed"}}
	denyRule["source"] = map[string]any{"kind": "refs", "refs": []any{prepared.References[0]}}
	rawDeny, _ := json.Marshal(denyRule)
	saved, err := s.Mutate(ctx, fixtureKey, "owner", bytes.NewReader(mutationBytes(t, initial.Bundle, `[{"stage":"invocation","action":"activate","rules":[`+string(rawDeny)+`]}]`)))
	require.NoError(t, err)
	require.Equal(t, "1", saved.Bundle.Revision)
	require.Equal(t, "1", saved.Bundle.ContextEpoch)

	// Normal primary failover: election_generation advances 1 -> 2 while
	// continuity-verified incarnation stays unchanged and RecoverAtLeast holds.
	txOld, err := s.Session.Begin()
	require.NoError(t, err)
	defer txOld.RollbackUnlessCommitted()
	oldRead, err := adapter.Begin(ctx, txOld)
	require.NoError(t, err)
	fencedRead := oldRead.(*FencedAuthorityRead)
	require.Equal(t, strings.Repeat("a", 32), fencedRead.Incarnation())
	require.Equal(t, uint64(1), fencedRead.ElectionGeneration())

	driver.mu.Lock()
	driver.generation = 2
	driver.mu.Unlock()
	fenceAfterFailover, err := adapter.RecoverAtLeast(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(2), fenceAfterFailover.ElectionGeneration)
	require.Equal(t, strings.Repeat("a", 32), fenceAfterFailover.Incarnation)

	// Old generation=1 in-flight session is fenced before commit.
	require.ErrorIs(t, oldRead.Validate(ctx), ErrUnavailable)
	txOld.RollbackUnlessCommitted()

	// Existing scope rows remain readable and mutable after failover because
	// AuthorityRead.Incarnation() tracks continuity-verified lineage, not election_generation.
	readAfterFailover, err := s.Get(ctx, fixtureKey, "owner")
	require.NoError(t, err)
	require.Equal(t, saved, readAfterFailover)

	// Departed member leaves space; choice-B unchanged departed-member DENY retention still holds under generation 2.
	_, err = s.Session.Exec(`UPDATE space_member SET status=0 WHERE uid='departed'`)
	require.NoError(t, err)
	retained, err := s.Mutate(ctx, fixtureKey, "owner", bytes.NewReader(mutationBytes(t, readAfterFailover.Bundle, `[{"stage":"invocation","action":"replace_rules","rules":[`+string(rawDeny)+`]}]`)))
	require.NoError(t, err)
	require.Equal(t, "2", retained.Bundle.Revision)

	// Post-COMMIT acknowledgement failure returns ErrReconcile and preserves committed state.
	driver.mu.Lock()
	driver.ackErr = ErrUnavailable
	driver.mu.Unlock()
	_, err = s.Mutate(ctx, fixtureKey, "owner", bytes.NewReader(mutationBytes(t, retained.Bundle, `[{"stage":"capability","action":"reset"}]`)))
	require.ErrorIs(t, err, ErrReconcile)
	require.ErrorIs(t, err, ErrUnavailable)
	driver.mu.Lock()
	driver.ackErr = nil
	driver.mu.Unlock()
	reconciled, err := s.Get(ctx, fixtureKey, "owner")
	require.NoError(t, err)
	require.Equal(t, "3", reconciled.Bundle.Revision)

	// Stale DB restore behind min_ack_position fails RecoverAtLeast closed.
	driver.mu.Lock()
	driver.checkpoint = driver.minAckPos - 1
	driver.mu.Unlock()
	_, err = adapter.RecoverAtLeast(ctx)
	require.ErrorIs(t, err, ErrUnavailable)

	// Discontinuous authority incarnation change fails closed on existing scope anchors.
	driver.mu.Lock()
	driver.checkpoint = driver.minAckPos
	driver.incarnation = strings.Repeat("b", 32)
	driver.mu.Unlock()
	_, err = adapter.RecoverAtLeast(ctx)
	require.ErrorIs(t, err, ErrUnavailable)
	rebuiltAdapter, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)
	s.Authority = rebuiltAdapter
	_, err = s.Get(ctx, fixtureKey, "owner")
	require.ErrorIs(t, err, ErrUnavailable)
}

type syntheticIMFactProvider struct {
	mu            sync.Mutex
	incarnation   string
	position      string
	nonce         string
	validateError error
	deliveries    map[string]IMResolvedDelivery
	historyItems  []IMHistoryHeaderItem
	disclosures   map[string]IMDisclosureItem
}

func newSyntheticIMFactProvider(t *testing.T) *syntheticIMFactProvider {
	t.Helper()
	dmRef, err := PairReference("bot", "peer")
	require.NoError(t, err)
	parentGroup := strings.Repeat("1", 32)
	threadRef := parentGroup + "____123456789012345"

	baseHeader := func(hdrRef, msgID string, src IMHeaderSource, parent *string, authorUID, authorKind string) IMHeaderRecord {
		return IMHeaderRecord{
			HeaderReference:      hdrRef,
			MessageID:            msgID,
			Source:               src,
			ParentGroup:          parent,
			SpaceID:              "space",
			AuthorUID:            authorUID,
			AuthorKind:           authorKind,
			RecipientBotUID:      "bot",
			NativeMessageVersion: "v1",
			PayloadSHA256:        strings.Repeat("d", 64),
			Delivery: IMDeliveryMetadata{
				StreamID:          "stream-bot-space",
				StreamIncarnation: strings.Repeat("2", 32),
				Sequence:          msgID,
			},
		}
	}

	dmHdr := baseHeader("hdr_dm_1", "101", IMHeaderSource{Kind: "dm", ID: dmRef["id"].(string)}, nil, "peer", "human")
	grpHdr := baseHeader("hdr_grp_1", "102", IMHeaderSource{Kind: "group", ID: "group"}, nil, "peer", "human")
	depGrpHdr := baseHeader("hdr_grp_departed", "103", IMHeaderSource{Kind: "group", ID: "group"}, nil, "departed", "human")
	thrHdr := baseHeader("hdr_thr_1", "104", IMHeaderSource{Kind: "thread", ID: threadRef}, &parentGroup, "peer", "human")
	sysHdr := baseHeader("hdr_sys_1", "105", IMHeaderSource{Kind: "group", ID: "group"}, nil, "system", "system")

	resolved := func(ref string, h IMHeaderRecord) IMResolvedDelivery {
		return IMResolvedDelivery{
			Reference:               ref,
			Status:                  "resolved",
			Header:                  h,
			MessageSourceExact:      true,
			MessageSpaceExact:       true,
			MessageAuthorExact:      true,
			MessageRecipientExact:   true,
			MessageVersionExact:     true,
			CallerCurrentRead:       true,
			BotCurrentRead:          true,
			CallerOriginalVisible:   true,
			BotOriginalVisible:      true,
			CallerParentCurrentRead: true,
			BotParentCurrentRead:    true,
			BotCurrentSend:          true,
		}
	}

	return &syntheticIMFactProvider{
		incarnation: strings.Repeat("3", 32),
		position:    "im_pos_42",
		nonce:       strings.Repeat("4", 32),
		deliveries: map[string]IMResolvedDelivery{
			"deliv_dm":       resolved("deliv_dm", dmHdr),
			"deliv_group":    resolved("deliv_group", grpHdr),
			"deliv_departed": resolved("deliv_departed", depGrpHdr),
			"deliv_thread":   resolved("deliv_thread", thrHdr),
			"deliv_system":   resolved("deliv_system", sysHdr),
		},
		historyItems: []IMHistoryHeaderItem{
			{Status: "resolved", Header: grpHdr},
		},
		disclosures: map[string]IMDisclosureItem{
			"hdr_grp_1": {
				Reference:       "hdr_grp_1",
				Status:          "resolved",
				Permit:          "permit_one_use_1",
				HeaderReference: "hdr_grp_1",
				PayloadSHA256:   strings.Repeat("d", 64),
			},
		},
	}
}

func (p *syntheticIMFactProvider) cut() IMAuthorityCut {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return IMAuthorityCut{
		AuthorityID: "im-native-v1",
		Incarnation: p.incarnation,
		Position:    p.position,
		ReadNonce:   p.nonce,
		StartedAt:   now,
		CompletedAt: now,
	}
}

func (p *syntheticIMFactProvider) InspectDeliveredHeadersV1(_ context.Context, _ Key, _ string, deliveryRefs []string) ([]IMResolvedDelivery, IMAuthorityCut, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]IMResolvedDelivery, 0, len(deliveryRefs))
	for _, ref := range deliveryRefs {
		if item, ok := p.deliveries[ref]; ok {
			out = append(out, item)
		} else {
			out = append(out, IMResolvedDelivery{
				Reference: ref,
				Status:    "unavailable",
				Reason:    "expired_reference",
			})
		}
	}
	return out, p.cut(), nil
}

func (p *syntheticIMFactProvider) ListHistoryHeadersV1(_ context.Context, _ Key, sourceRef string, _ *string, _ uint64) (IMHistoryHeadersPage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return IMHistoryHeadersPage{
		SourceReference: sourceRef,
		PageID:          strings.Repeat("5", 32),
		Items:           append([]IMHistoryHeaderItem(nil), p.historyItems...),
		NextCursor:      nil,
		End:             true,
		Cut:             p.cut(),
	}, nil
}

func (p *syntheticIMFactProvider) IssueHistoryDisclosureV1(_ context.Context, _ Key, _, _ string, headerRefs []string) ([]IMDisclosureItem, IMAuthorityCut, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]IMDisclosureItem, 0, len(headerRefs))
	for _, ref := range headerRefs {
		if item, ok := p.disclosures[ref]; ok {
			out = append(out, item)
		} else {
			out = append(out, IMDisclosureItem{
				Reference: ref,
				Status:    "unavailable",
				Reason:    "disclosure_unavailable",
			})
		}
	}
	return out, p.cut(), nil
}

func (p *syntheticIMFactProvider) ValidateIMCut(_ context.Context, _ Key, authorityID, incarnation, position, readNonce string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.validateError != nil {
		return p.validateError
	}
	if authorityID != "im-native-v1" || incarnation != p.incarnation || position != p.position || readNonce != p.nonce {
		return ErrUnavailable
	}
	return nil
}

func seedAdapterTables(t *testing.T, s Store) {
	t.Helper()
	parentGroup := strings.Repeat("1", 32)
	for _, q := range []string{
		`CREATE TABLE group_member(group_no TEXT,uid TEXT,status INTEGER,is_deleted INTEGER,is_external INTEGER,UNIQUE(group_no,uid))`,
		`CREATE TABLE friend(uid TEXT,to_uid TEXT,is_deleted INTEGER,is_alone INTEGER,UNIQUE(uid,to_uid))`,
		`CREATE TABLE user_setting(uid TEXT,to_uid TEXT,blacklist INTEGER,UNIQUE(uid,to_uid))`,
		"INSERT INTO `group` VALUES('" + parentGroup + "','space',1)",
		`INSERT INTO thread VALUES('` + parentGroup + `','123456789012345',1)`,
		`INSERT INTO group_member VALUES('group','bot',1,0,0),('group','peer',1,0,0),('group','departed',1,1,0)`,
		`INSERT INTO group_member VALUES('` + parentGroup + `','bot',1,0,0),('` + parentGroup + `','peer',1,0,0)`,
		`INSERT INTO friend VALUES('peer','bot',0,0),('bot','peer',0,0)`,
		`INSERT INTO user_setting VALUES('peer','bot',0),('bot','peer',0)`,
	} {
		_, err := s.Session.Exec(q)
		require.NoError(t, err)
	}
}

func TestSQLNativeFactAdapterAllArmsProfilesAndPlainSyncRejection(t *testing.T) {
	for _, badMode := range []string{
		"",
		"none",
		"im_sync_channel_message",
		"plain_message_sync",
		"bot_api_sync",
		"messages_sync",
		"webhook_mirror",
		"message_mirror",
		"sql_message_mirror",
	} {
		require.ErrorIs(t, RejectPlainMessageSyncFactSource(badMode), ErrUnavailable, "mode=%s", badMode)
	}
	require.NoError(t, RejectPlainMessageSyncFactSource(NativeFactProviderModeIMV1))

	ctx := t.Context()
	driver := newSyntheticExternalAuthorityDriver(fixturePin.Digest)
	authority, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "native-adapter.sqlite")
	s := fixtureStore(t, path)
	s.Authority = authority
	seed(t, s)
	seedAdapterTables(t, s)

	imProvider := newSyntheticIMFactProvider(t)
	factAdapter, err := NewSQLNativeFactAdapter(authority, imProvider)
	require.NoError(t, err)
	factAdapter.testNoLocks = true

	c := &config.Context{}
	require.NoError(t, Install(c, s, fixturePin, factAdapter))
	rt := RuntimeFor(c)
	require.NotNil(t, rt)
	require.True(t, rt.HasFacts())

	for _, purpose := range []string{"admit", "contributor", "reply"} {
		t.Run("resolve_"+purpose, func(t *testing.T) {
			req := map[string]any{
				"schema_version":  json.Number("1"),
				"profile_version": json.Number("1"),
				"request_id":      strings.Repeat("a", 32),
				"operation":       "resolve",
				"purpose":         purpose,
				"references": []any{
					map[string]any{"delivery_reference": "deliv_dm"},
					map[string]any{"delivery_reference": "deliv_group"},
					map[string]any{"delivery_reference": "deliv_departed"},
					map[string]any{"delivery_reference": "deliv_thread"},
					map[string]any{"delivery_reference": "deliv_system"},
					map[string]any{"delivery_reference": "deliv_missing"},
				},
			}
			out, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(req)))
			require.NoError(t, err)
			decoded := fixtureObject(t, out)
			results := decoded["results"].([]any)
			require.Len(t, results, 6)

			dmRow := results[0].(map[string]any)
			require.Equal(t, "dm_"+purpose+"_v1", dmRow["profile"])
			require.Equal(t, true, dmRow["predicates"].(map[string]any)["dm_human_blocks_bot_clear"])

			grpRow := results[1].(map[string]any)
			require.Equal(t, "group_"+purpose+"_v1", grpRow["profile"])
			require.Equal(t, true, grpRow["predicates"].(map[string]any)["bot_group_active_member"])

			depRow := results[2].(map[string]any)
			require.Equal(t, "group_"+purpose+"_v1", depRow["profile"])
			if purpose != "reply" {
				require.Equal(t, false, depRow["predicates"].(map[string]any)["caller_group_active_member"])
			}

			thrRow := results[3].(map[string]any)
			require.Equal(t, "thread_"+purpose+"_v1", thrRow["profile"])
			require.Equal(t, true, thrRow["predicates"].(map[string]any)["thread_not_deleted"])

			sysRow := results[4].(map[string]any)
			require.Equal(t, "unsupported_principal_v1", sysRow["profile"])
			require.Equal(t, false, sysRow["predicates"].(map[string]any)["identity_supported"])

			missingRow := results[5].(map[string]any)
			require.Equal(t, "unavailable", missingRow["status"])
			require.Equal(t, "expired_reference", missingRow["reason"])
		})
	}

	// Blacklist update in SQL produces known-negative dm_human_blocks_bot_clear=false.
	_, err = s.Session.Exec(`UPDATE user_setting SET blacklist=1 WHERE uid='peer' AND to_uid='bot'`)
	require.NoError(t, err)
	dmReq := map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("b", 32),
		"operation":       "resolve",
		"purpose":         "admit",
		"references":      []any{map[string]any{"delivery_reference": "deliv_dm"}},
	}
	out, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(dmReq)))
	require.NoError(t, err)
	require.Contains(t, string(out), `"dm_human_blocks_bot_clear":false`)

	// History headers arm.
	histReq := map[string]any{
		"schema_version":   json.Number("1"),
		"profile_version":  json.Number("1"),
		"request_id":       strings.Repeat("c", 32),
		"operation":        "history_headers",
		"source_reference": "src_group_1",
		"cursor":           nil,
		"page_size":        json.Number("2"),
	}
	out, err = rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(histReq)))
	require.NoError(t, err)
	require.Contains(t, string(out), `"header_reference":"hdr_grp_1"`)

	// History disclosure arm: epoch "0" matches initial stored bundle; epoch "9" is rejected as expired_reference.
	discReq := map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("d", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("f", 32),
		"context_epoch":   "0",
		"headers":         []any{map[string]any{"header_reference": "hdr_grp_1"}},
	}
	out, err = rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(discReq)))
	require.NoError(t, err)
	require.Contains(t, string(out), `"permit":"permit_one_use_1"`)

	discReq["context_epoch"] = "9"
	out, err = rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(discReq)))
	require.NoError(t, err)
	require.Contains(t, string(out), `"reason":"expired_reference"`)

	// IM cut validation failure rejects the fact read closed.
	imProvider.mu.Lock()
	imProvider.validateError = ErrUnavailable
	imProvider.mu.Unlock()
	_, err = rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(histReq)))
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestInstallOptInAndEnvWiringFailsClosedWithoutAuthorityAndServesWhenValid(t *testing.T) {
	// Default disabled opt-in is a clean no-op.
	emptyCtx := &config.Context{}
	require.NoError(t, InstallOptIn(emptyCtx, InstallConfig{Enabled: false}))
	require.Nil(t, RuntimeFor(emptyCtx))

	t.Setenv(EnvPermissionBundleEnabled, "0")
	require.NoError(t, InstallFromEnv(emptyCtx, nil, nil))
	require.Nil(t, RuntimeFor(emptyCtx))

	// Opt-in enabled without FencedAuthority or with local SQL writable/same-DB substitutes fails closed.
	path := filepath.Join(t.TempDir(), "optin.sqlite")
	baseStore := fixtureStore(t, path)
	for _, cfg := range []InstallConfig{
		{
			Enabled:       true,
			Session:       baseStore.Session,
			Origin:        fixtureKey.Origin,
			Pin:           fixturePin,
			Releases:      fixtureReleases{},
			AuthorityMode: AuthorityModeExternalFencedV1,
		},
		{
			Enabled:         true,
			Session:         baseStore.Session,
			Origin:          fixtureKey.Origin,
			Pin:             fixturePin,
			Releases:        fixtureReleases{},
			AuthorityMode:   "sql_read_only_variables",
			AuthorityDriver: newSyntheticExternalAuthorityDriver(fixturePin.Digest),
		},
		{
			Enabled:         true,
			Session:         baseStore.Session,
			Origin:          fixtureKey.Origin,
			Pin:             fixturePin,
			Releases:        fixtureReleases{},
			AuthorityMode:   "same_db_counter",
			AuthorityDriver: newSyntheticExternalAuthorityDriver(fixturePin.Digest),
		},
		{
			Enabled:          true,
			Session:          baseStore.Session,
			Origin:           fixtureKey.Origin,
			Pin:              fixturePin,
			Releases:         fixtureReleases{},
			AuthorityMode:    AuthorityModeExternalFencedV1,
			AuthorityDriver:  newSyntheticExternalAuthorityDriver(fixturePin.Digest),
			FactProviderMode: "im_sync_channel_message",
		},
	} {
		c := &config.Context{}
		err := InstallOptIn(c, cfg)
		require.ErrorIs(t, err, ErrUnavailable)
		require.Nil(t, RuntimeFor(c))
	}

	// Stage the real CLI v2 candidate + source-slot-witness-v5.json.gz into an operator directory and opt in.
	candInput, _ := cliCandidatePackageV5(t)
	catDir := filepath.Join(t.TempDir(), "catalog-v2")
	for rel, data := range candInput.Files {
		full := filepath.Join(catDir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0700))
		require.NoError(t, os.WriteFile(full, data, 0600))
	}
	witnessPath := filepath.Join(t.TempDir(), "source-slot-witness-v5.json.gz")
	witnessRaw, err := os.ReadFile("testdata/source-slot-witness-v5.json.gz")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(witnessPath, witnessRaw, 0600))

	driver := newSyntheticExternalAuthorityDriver(candInput.Pin.Digest)
	imProvider := newSyntheticIMFactProvider(t)
	validCtx := &config.Context{}
	require.NoError(t, InstallOptIn(validCtx, InstallConfig{
		Enabled:           true,
		Session:           baseStore.Session,
		Origin:            fixtureKey.Origin,
		Pin:               candInput.Pin,
		CatalogDir:        catDir,
		SlotWitnessPath:   witnessPath,
		SlotWitnessSHA256: "0c5da173bd0f53c64562a70a5c5feebc955ad111bbe84ed11f5588c08b4b9c0b",
		AuthorityMode:     AuthorityModeExternalFencedV1,
		AuthorityDriver:   driver,
		FactProviderMode:  NativeFactProviderModeIMV1,
		IMFactProvider:    imProvider,
		testNoLocks:       true,
	}))
	rt := RuntimeFor(validCtx)
	require.NotNil(t, rt)
	require.NotNil(t, rt.Store())
	require.True(t, rt.HasFacts())

	seed(t, *rt.Store(), candInput.Pin)
	seedAdapterTables(t, *rt.Store())

	// Mount Owner and Bot routes against the installed runtime and verify end-to-end HTTP serving.
	router := wkhttp.New()
	router.SetErrorRenderer(i18n.NewErrorRenderer(i18n.NewLocalizer(i18n.DefaultLanguage)))
	router.GET("/v1/robot/:robot_id/permission-bundle/v1", func(c *wkhttp.Context) { rt.Store().Serve(c, c.Param("robot_id"), "owner", "owner_get") })
	router.POST("/v1/robot/:robot_id/permission-bundle/v1/prepare", func(c *wkhttp.Context) { rt.Store().Serve(c, c.Param("robot_id"), "owner", "prepare") })
	router.GET("/v1/robot/:robot_id/permission-bundle/v1/catalog", func(c *wkhttp.Context) { rt.Store().Serve(c, c.Param("robot_id"), "owner", "catalog") })
	router.GET("/v1/robot/:robot_id/permission-bundle/v1/catalog/file", func(c *wkhttp.Context) { rt.Store().Serve(c, c.Param("robot_id"), "owner", "catalog_file") })
	router.GET("/v1/bot/permission-bundle/v1", func(c *wkhttp.Context) { rt.Store().Serve(c, "bot", "", "self") })
	router.POST("/v1/bot/permission-facts/v1", func(c *wkhttp.Context) {
		space, e := ExplicitSpace(c.Request)
		if e != nil {
			RespondError(c, e)
			return
		}
		out, e := rt.Facts(c.Request.Context(), Key{Origin: rt.Store().Origin, BotUID: "bot", SpaceID: space}, c.Request.Body)
		if e != nil {
			RespondError(c, e)
			return
		}
		c.Data(http.StatusOK, "application/json; charset=utf-8", out)
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/robot/bot/permission-bundle/v1?space_id=space", nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"catalog_format":"permission-catalog-package-v2"`)

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/robot/bot/permission-bundle/v1/catalog?"+catalogQuery(candInput.Pin, ""), nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, candInput.Files["manifest.json"], rec.Body.Bytes())

	factReq := map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("e", 32),
		"operation":       "resolve",
		"purpose":         "admit",
		"references":      []any{map[string]any{"delivery_reference": "deliv_group"}},
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/bot/permission-facts/v1?space_id=space", bytes.NewReader(canonical(factReq))))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"profile":"group_admit_v1"`)
}

func TestContractManifestV4AndV5ByteAndHashIntegrity(t *testing.T) {
	for _, manifestName := range []string{"contract-manifest-v4.json", "contract-manifest-v5.json", "contract-manifest-v6.json", "contract-manifest-v7.json", "contract-manifest-v8.json", "contract-manifest-v9.json", "contract-manifest-v10.json"} {
		t.Run(manifestName, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("contracts", manifestName))
			require.NoError(t, err)
			var m struct {
				Files map[string]struct {
					Bytes  int    `json:"bytes"`
					SHA256 string `json:"sha256"`
				} `json:"files"`
			}
			require.NoError(t, json.Unmarshal(raw, &m))
			require.NotEmpty(t, m.Files)
			for relPath, expected := range m.Files {
				fullPath := filepath.Join("..", "..", filepath.FromSlash(relPath))
				data, err := os.ReadFile(fullPath)
				require.NoError(t, err, relPath)
				require.Equal(t, expected.Bytes, len(data), relPath)
				require.Equal(t, expected.SHA256, independentHash(data), relPath)
			}
		})
	}
}

func TestNativeSingleWriterLineageAuthorityStartupRestartAndFailClosedBoundaries(t *testing.T) {
	ctx := t.Context()
	dbFile := filepath.Join(t.TempDir(), "native-lineage.sqlite")
	f := newServerFacts(t)
	_ = dbFile

	candInput, _ := cliCandidatePackageV5(t)
	catDir := filepath.Join(t.TempDir(), "catalog-v2")
	for rel, data := range candInput.Files {
		full := filepath.Join(catDir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
		require.NoError(t, os.WriteFile(full, data, 0o600))
	}
	witnessPath := filepath.Join(t.TempDir(), "source-slot-witness-v5.json.gz")
	witnessRaw, err := os.ReadFile("testdata/source-slot-witness-v5.json.gz")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(witnessPath, witnessRaw, 0o600))
	const witnessSHA256 = "0c5da173bd0f53c64562a70a5c5feebc955ad111bbe84ed11f5588c08b4b9c0b"

	statePath := filepath.Join(t.TempDir(), "authority-state.json")
	incarnation := strings.Repeat("5", 32)
	keyBytes := []byte(strings.Repeat("k", 32))

	baseCfg := InstallConfig{
		Enabled:                   true,
		Session:                   f.s.Session,
		Origin:                    fixtureKey.Origin,
		Pin:                       candInput.Pin,
		CatalogDir:                catDir,
		SlotWitnessPath:           witnessPath,
		SlotWitnessSHA256:         witnessSHA256,
		AuthorityMode:             AuthorityModeNativeSingleWriterV1,
		AuthorityID:               "sql-native-writer",
		AuthorityIncarnation:      incarnation,
		AuthorityStatePath:        statePath,
		AuthorityKey:              keyBytes,
		FactProviderMode:          NativeFactProviderModeServerStoreV1,
		ServerMessageHooks:        testServerHooks(),
		ServerStoreAuthorityID:    "octo-server-message-store",
		ServerStoreIncarnation:    incarnation,
		ServerPermitKey:           keyBytes,
		ServerDurablePermitLedger: true,
		testNoLocks:               true,
	}

	// 0. Existing bot_permission_scope row (from newServerFacts) when AuthorityStatePath is missing
	// fails closed even when AuthorityProvision=true (refuses to bootstrap over existing scopes or mismatched incarnation).
	cPreExisting := &config.Context{}
	cfgPreExisting := baseCfg
	cfgPreExisting.AuthorityProvision = true
	require.ErrorIs(t, InstallOptIn(cPreExisting, cfgPreExisting), ErrUnavailable)
	require.Nil(t, RuntimeFor(cPreExisting))

	// Clear the pre-seeded scope row and add bot_token column so BeginAssociation/CommitAssociations can provision cleanly.
	_, err = f.s.Session.Exec(`DELETE FROM bot_permission_scope`)
	require.NoError(t, err)
	_, err = f.s.Session.Exec(`ALTER TABLE robot ADD COLUMN bot_token TEXT DEFAULT 'bf_synthetic'`)
	require.NoError(t, err)

	// 1. Unprovisioned state with AuthorityProvision=false fails closed.
	cUnprov := &config.Context{}
	cfgUnprov := baseCfg
	cfgUnprov.AuthorityProvision = false
	require.ErrorIs(t, InstallOptIn(cUnprov, cfgUnprov), ErrUnavailable)
	require.Nil(t, RuntimeFor(cUnprov))

	// 2. Missing incarnation, short key, or missing state path fails closed even with AuthorityProvision=true.
	for _, mutate := range []func(*InstallConfig){
		func(ic *InstallConfig) { ic.AuthorityIncarnation = ""; ic.ServerStoreIncarnation = "" },
		func(ic *InstallConfig) { ic.AuthorityKey = []byte("short"); ic.ServerPermitKey = []byte("short") },
		func(ic *InstallConfig) { ic.AuthorityStatePath = "" },
	} {
		cBad := &config.Context{}
		cfgBad := baseCfg
		cfgBad.AuthorityProvision = true
		mutate(&cfgBad)
		require.ErrorIs(t, InstallOptIn(cBad, cfgBad), ErrUnavailable)
		require.Nil(t, RuntimeFor(cBad))
	}

	// 3. Initial bootstrap with AuthorityProvision=true succeeds and creates SQL + 0600 host state.
	c1 := &config.Context{}
	cfg1 := baseCfg
	cfg1.AuthorityProvision = true
	require.NoError(t, InstallOptIn(c1, cfg1))
	require.NoError(t, VerifyAfterSetup(c1))
	rt1 := RuntimeFor(c1)
	require.NotNil(t, rt1)
	require.True(t, rt1.HasFacts())
	require.True(t, rt1.HasDeliveryBinding())

	stInfo, err := os.Lstat(statePath)
	require.NoError(t, err)
	require.True(t, stInfo.Mode().IsRegular())
	require.Zero(t, stInfo.Mode().Perm()&0o077)

	// 4. Before scope provisioning, native facts and self-read fail closed (never auto-provision on read/recovery).
	_, err = rt1.Store().Self(ctx, fixtureKey)
	require.ErrorIs(t, err, ErrUnavailable)
	probeReq := map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("1", 32),
		"operation":       "resolve",
		"purpose":         "admit",
		"references":      []any{map[string]any{"delivery_reference": "s1-1-00-1-0"}},
	}
	_, err = rt1.Facts(ctx, fixtureKey, bytes.NewReader(canonical(probeReq)))
	require.ErrorIs(t, err, ErrUnavailable)

	// 5. Provision bot scope via BeginAssociation + CommitAssociations.
	txAssoc, cancelAssoc, err := BeginAssociation(c1, f.s.Session)
	require.NoError(t, err)
	defer cancelAssoc()
	require.NoError(t, CommitAssociations(c1, txAssoc, Association{BotUID: fixtureKey.BotUID, SpaceID: fixtureKey.SpaceID, New: true}))

	// 6. Seed a space-tagged DM message and exercise Self, BindDeliveredMessage, Resolve, and HistoryDisclosure under Process 1.
	dmPayload := map[string]any{"type": 1, "space_id": "space", "content": "NATIVE-STARTUP-SECRET"}
	dmDigest := sha256OfJSON(dmPayload)
	f.msg("8801", 1, "peer", f.dmChan, 1, dmPayload)

	bundle1, err := rt1.Store().Self(ctx, fixtureKey)
	require.NoError(t, err)
	require.Equal(t, "0", bundle1.Revision)
	require.Equal(t, "0", bundle1.ContextEpoch)
	require.Equal(t, candInput.Pin.Digest, bundle1.CatalogDigest)

	bindOut1, err := rt1.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-native-bind-1",
		"channel_type":            json.Number("1"),
		"channel_id":              f.dmChan,
		"message_id":              "8801",
		"message_seq":             "1",
		"from_uid":                "peer",
		"observed_payload_sha256": dmDigest,
	})))
	require.NoError(t, err)
	bindObj1 := fixtureObject(t, bindOut1)["binding"].(map[string]any)
	require.Equal(t, "bound", bindObj1["status"])
	delivRef := bindObj1["delivery_reference"].(string)
	hdrRef := bindObj1["header_reference"].(string)

	discOut1, err := rt1.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("2", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("c", 32),
		"context_epoch":   "0",
		"headers":         []any{map[string]any{"header_reference": hdrRef}},
	})))
	require.NoError(t, err)
	discRes1 := fixtureObject(t, discOut1)["results"].([]any)[0].(map[string]any)
	require.Equal(t, "resolved", discRes1["status"])
	permit1 := discRes1["permit"].(string)
	rt1Provider := rt1.facts.(*SQLNativeFactAdapter).IMProvider.(*ServerMessageFactProvider)
	require.NoError(t, rt1Provider.ConsumeDisclosurePermitContext(ctx, fixtureKey, strings.Repeat("c", 32), "0", hdrRef, dmDigest, permit1))

	// 7. Normal process restart (AuthorityProvision=false) on the same SQL store and AuthorityStatePath:
	// bumps election_generation (1 -> 2), fences Process 1, preserves incarnation, and serves under Process 2.
	c2 := &config.Context{}
	cfg2 := baseCfg
	cfg2.AuthorityProvision = false
	require.NoError(t, InstallOptIn(c2, cfg2))
	require.NoError(t, VerifyAfterSetup(c2))
	rt2 := RuntimeFor(c2)
	require.NotNil(t, rt2)

	// Stale writer (Process 1) is now fenced out and fails closed on both policy and fact reads.
	_, err = rt1.Store().Self(ctx, fixtureKey)
	require.ErrorIs(t, err, ErrUnavailable, "superseded writer process must fail closed")
	_, err = rt1.Facts(ctx, fixtureKey, bytes.NewReader(canonical(probeReq)))
	require.ErrorIs(t, err, ErrUnavailable, "superseded writer process must fail closed on facts")

	// Restarted writer (Process 2) serves Self and Facts with the same 32-hex incarnation and higher position.
	bundle2, err := rt2.Store().Self(ctx, fixtureKey)
	require.NoError(t, err)
	require.Equal(t, bundle1.Incarnation, bundle2.Incarnation)
	require.Equal(t, bundle1.Digest, bundle2.Digest)

	resOut2, err := rt2.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("3", 32),
		"operation":       "resolve",
		"purpose":         "admit",
		"references":      []any{map[string]any{"delivery_reference": delivRef}},
	})))
	require.NoError(t, err)
	resEnv2 := fixtureObject(t, resOut2)
	auths2 := resEnv2["authorities"].([]any)
	require.Len(t, auths2, 2)
	for _, rawAuth := range auths2 {
		a := rawAuth.(map[string]any)
		require.Equal(t, incarnation, a["incarnation"])
		require.Equal(t, "ack_before_read_start", a["consistency"])
	}

	// Consumed permit from Process 1 remains unavailable across Process 2 restart.
	discOut2, err := rt2.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("4", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("c", 32),
		"context_epoch":   "0",
		"headers":         []any{map[string]any{"header_reference": hdrRef}},
	})))
	require.NoError(t, err)
	discRes2 := fixtureObject(t, discOut2)["results"].([]any)[0].(map[string]any)
	require.Equal(t, "unavailable", discRes2["status"])
	require.Equal(t, "disclosure_unavailable", discRes2["reason"])

	// 8. Negative restart checks: wrong incarnation, wrong key, regressed SQL position, or lost state file fail closed.
	cWrongInc := &config.Context{}
	cfgWrongInc := baseCfg
	cfgWrongInc.AuthorityIncarnation = strings.Repeat("9", 32)
	cfgWrongInc.ServerStoreIncarnation = strings.Repeat("9", 32)
	require.ErrorIs(t, InstallOptIn(cWrongInc, cfgWrongInc), ErrUnavailable)

	cWrongKey := &config.Context{}
	cfgWrongKey := baseCfg
	cfgWrongKey.AuthorityKey = []byte(strings.Repeat("z", 32))
	require.ErrorIs(t, InstallOptIn(cWrongKey, cfgWrongKey), ErrUnavailable)

	// Simulate SQL rollback / stale restore behind host state checkpoint.
	var savedAck, savedCommit, savedCheck int64
	var savedWriterID, savedHMAC string
	require.NoError(t, f.s.Session.QueryRow(`SELECT active_writer_id,committed_position,acknowledged_position,recoverable_scope_checkpoint,state_hmac FROM `+NativeAuthorityLineageTable+` WHERE singleton=1`).Scan(&savedWriterID, &savedCommit, &savedAck, &savedCheck, &savedHMAC))

	regressedDriver, err := NewNativeSingleWriterLineageDriver(NativeSingleWriterLineageConfig{
		Session:       f.s.Session,
		Origin:        fixtureKey.Origin,
		AuthorityID:   "sql-native-writer",
		Incarnation:   incarnation,
		CatalogDigest: candInput.Pin.Digest,
		StatePath:     statePath,
		Key:           keyBytes,
		testNoLocks:   true,
	})
	require.NoError(t, err)
	regressedRow := nativeAuthoritySQLRow{
		AuthorityID:                "sql-native-writer",
		Incarnation:                incarnation,
		CatalogDigest:              candInput.Pin.Digest,
		ElectionGeneration:         1,
		ActiveWriterID:             strings.Repeat("a", 32),
		CommittedPosition:          1,
		AcknowledgedPosition:       1,
		RecoverableScopeCheckpoint: 1,
	}
	regressedRow.StateHMAC = regressedDriver.sqlStateMAC(regressedRow)
	_, err = f.s.Session.Exec(`UPDATE `+NativeAuthorityLineageTable+` SET election_generation=1,active_writer_id=?,committed_position=1,acknowledged_position=1,recoverable_scope_checkpoint=1,state_hmac=? WHERE singleton=1`, regressedRow.ActiveWriterID, regressedRow.StateHMAC)
	require.NoError(t, err)

	cRegressed := &config.Context{}
	require.ErrorIs(t, InstallOptIn(cRegressed, baseCfg), ErrUnavailable, "SQL rollback behind host state checkpoint must fail closed")

	// Restore SQL row, then simulate host journal loss (missing statePath) while SQL lineage exists.
	_, err = f.s.Session.Exec(`UPDATE `+NativeAuthorityLineageTable+` SET election_generation=2,active_writer_id=?,committed_position=?,acknowledged_position=?,recoverable_scope_checkpoint=?,state_hmac=? WHERE singleton=1`, savedWriterID, savedCommit, savedAck, savedCheck, savedHMAC)
	require.NoError(t, err)
	savedHostBytes, err := os.ReadFile(statePath)
	require.NoError(t, err)
	require.NoError(t, os.Remove(statePath))

	cJournalLost := &config.Context{}
	cfgJournalLost := baseCfg
	cfgJournalLost.AuthorityProvision = true
	require.ErrorIs(t, InstallOptIn(cJournalLost, cfgJournalLost), ErrUnavailable, "missing host state file against existing SQL lineage must fail closed even when Provision=true")

	// Restore host state file and verify clean restart succeeds again.
	require.NoError(t, os.WriteFile(statePath, savedHostBytes, 0o600))
	c3 := &config.Context{}
	require.NoError(t, InstallOptIn(c3, baseCfg))
	require.NotNil(t, RuntimeFor(c3))
}
