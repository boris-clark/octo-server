package permissionbundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Mininglamp-OSS/octo-lib/config"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gocraft/dbr/v2"
	"github.com/gocraft/dbr/v2/dialect"
	"github.com/stretchr/testify/require"
)

func testServerHooks() ServerMessageHooks {
	return ServerMessageHooks{
		MessageTable:          func(string) string { return "message" },
		MessageUserExtraTable: func(string) string { return "message_user_extra" },
		ChannelOffsetTable:    func(string) string { return "channel_offset" },
		PayloadVisibleTo: func(payload []byte, uid string) bool {
			var v struct {
				Visibles []string `json:"visibles"`
			}
			if json.Unmarshal(payload, &v) != nil || len(v.Visibles) == 0 {
				return true
			}
			for _, x := range v.Visibles {
				if x == uid {
					return true
				}
			}
			return false
		},
		PayloadSpaceID: func(payload []byte) string {
			var v struct {
				SpaceID string `json:"space_id"`
			}
			_ = json.Unmarshal(payload, &v)
			return v.SpaceID
		},
		IsSystemUID: func(uid string) bool { return uid == "system" },
	}
}

type serverFacts struct {
	t        *testing.T
	s        Store
	p        *ServerMessageFactProvider
	dmChan   string
	parent   string
	threadCh string
}

func newServerFacts(t *testing.T) *serverFacts {
	path := filepath.Join(t.TempDir(), "server-facts.sqlite")
	s := fixtureStore(t, path)
	seed(t, s)
	seedAdapterTables(t, s)
	pair, err := PairReference("bot", "peer")
	require.NoError(t, err)
	parent := strings.Repeat("1", 32)
	for _, q := range []string{
		"CREATE TABLE message(message_id TEXT,message_seq INTEGER,from_uid TEXT,channel_id TEXT,channel_type INTEGER,`timestamp` INTEGER,payload BLOB,is_deleted INTEGER,expire INTEGER DEFAULT 0)",
		"CREATE TABLE message_extra(message_id TEXT UNIQUE,version INTEGER,revoke INTEGER,is_deleted INTEGER,content_edit TEXT,content_edit_hash TEXT)",
		"CREATE TABLE message_user_extra(uid TEXT,message_id TEXT,message_is_deleted INTEGER)",
		"CREATE TABLE channel_offset(uid TEXT,channel_id TEXT,channel_type INTEGER,message_seq INTEGER)",
		"CREATE TABLE channel_setting(channel_id TEXT,channel_type INTEGER,offset_message_seq INTEGER)",
	} {
		_, err := s.Session.Exec(q)
		require.NoError(t, err)
	}
	p, err := NewServerMessageFactProvider(ServerMessageFactConfig{
		Session: s.Session, Hooks: testServerHooks(), StoreIncarnation: strings.Repeat("5", 32), PermitKey: []byte(strings.Repeat("k", 32)),
	})
	require.NoError(t, err)
	return &serverFacts{t: t, s: s, p: p, dmChan: pair["id"].(string), parent: parent, threadCh: parent + "____123456789012345"}
}

func (f *serverFacts) msg(id string, seq int, from, channel string, ctype int, payload map[string]any) {
	f.msgWithExpire(id, seq, from, channel, ctype, int64(1700000000+seq), 0, payload)
}

func (f *serverFacts) msgWithExpire(id string, seq int, from, channel string, ctype int, ts, expire int64, payload map[string]any) {
	b, _ := json.Marshal(payload)
	_, err := f.s.Session.Exec("INSERT INTO message VALUES(?,?,?,?,?,?,?,0,?)", id, seq, from, channel, ctype, ts, b, expire)
	require.NoError(f.t, err)
}

func (f *serverFacts) exec(q string, args ...any) {
	_, err := f.s.Session.Exec(q, args...)
	require.NoError(f.t, err)
}

func (f *serverFacts) resolve(purpose string, refs ...string) []IMResolvedDelivery {
	out, cut, err := f.p.InspectDeliveredHeadersV1(f.t.Context(), fixtureKey, purpose, refs)
	require.NoError(f.t, err)
	require.Len(f.t, out, len(refs))
	require.NoError(f.t, f.p.ValidateIMCut(f.t.Context(), fixtureKey, cut.AuthorityID, cut.Incarnation, cut.Position, cut.ReadNonce))
	return out
}

func curVersion(id string, f *serverFacts) string {
	r := f.resolve("admit", ServerDeliveryReference(1, f.dmChan, id, "x0_0"))
	return r[0].Header.NativeMessageVersion
}

func TestServerMessageFactsDMPositivePathAndUnknowns(t *testing.T) {
	f := newServerFacts(t)
	f.msg("1001", 1, "peer", f.dmChan, 1, map[string]any{"type": 1, "content": "SECRET-BODY", "space_id": "space"})
	f.msg("1002", 2, "peer", f.dmChan, 1, map[string]any{"type": 1, "content": "untagged"})
	f.msg("1003", 3, "peer", f.dmChan, 1, map[string]any{"type": 1, "content": "other space", "space_id": "elsewhere"})

	ok := f.resolve("admit", ServerDeliveryReference(1, f.dmChan, "1001", "x0_0"))[0]
	require.Equal(t, "resolved", ok.Status)
	require.True(t, ok.MessageSourceExact && ok.MessageSpaceExact && ok.MessageAuthorExact && ok.MessageRecipientExact && ok.MessageVersionExact)
	require.True(t, ok.CallerCurrentRead && ok.BotCurrentRead && ok.CallerOriginalVisible && ok.BotOriginalVisible)
	require.Equal(t, "human", ok.Header.AuthorKind)
	require.Equal(t, "dm", ok.Header.Source.Kind)
	require.Equal(t, "1001", ok.Header.MessageID)
	// metadata only: nothing in the header carries the body.
	raw, _ := json.Marshal(ok.Header)
	require.NotContains(t, string(raw), "SECRET-BODY")
	sum := sha256.Sum256([]byte(`{"content":"SECRET-BODY","space_id":"space","type":1}`))
	require.Equal(t, hex.EncodeToString(sum[:]), ok.Header.PayloadSHA256)

	// Unknown version: reference without version is non-serving, not true.
	nv := f.resolve("admit", ServerDeliveryReference(1, f.dmChan, "1001", ""))[0]
	require.True(t, nv.MessageVersionUnknown)
	require.False(t, nv.MessageVersionExact)
	require.Equal(t, "predicate_unsupported", nv.unknownReason("admit"))

	// Untagged DM space is unknown; cross-space tag is a definite false.
	un := f.resolve("admit", ServerDeliveryReference(1, f.dmChan, "1002", "x0_0"))[0]
	require.True(t, un.MessageSpaceUnknown)
	require.False(t, un.MessageSpaceExact)
	cs := f.resolve("admit", ServerDeliveryReference(1, f.dmChan, "1003", "x0_0"))[0]
	require.False(t, cs.MessageSpaceUnknown)
	require.False(t, cs.MessageSpaceExact)
}

func TestServerMessageFactsMissingRevokedDeletedAndMalformed(t *testing.T) {
	f := newServerFacts(t)
	f.msg("2001", 1, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space"})
	f.msg("2002", 2, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space"})
	f.msg("2003", 3, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space"})
	f.exec("INSERT INTO message_extra VALUES('2002',5,1,0,NULL,'')")
	f.exec("INSERT INTO message_extra VALUES('2003',6,0,1,NULL,'')")
	f.exec("UPDATE message SET is_deleted=1 WHERE message_id='2001'")

	for id, reason := range map[string]string{"2001": "expired_reference", "2002": "expired_reference", "2003": "expired_reference", "9999": "mirror_lag"} {
		r := f.resolve("admit", ServerDeliveryReference(1, f.dmChan, id, "x0_0"))[0]
		require.Equal(t, "unavailable", r.Status, id)
		require.Equal(t, reason, r.Reason, id)
	}
	// Malformed and foreign-channel references are non-serving, never errors that leak.
	bad := f.resolve("admit", "not-a-ref", ServerDeliveryReference(1, "x@y", "2001", "x0_0"), ServerDeliveryReference(9, f.dmChan, "2001", ""))
	for _, r := range bad {
		require.Equal(t, "unavailable", r.Status)
		require.Equal(t, "predicate_unsupported", r.Reason)
	}
}

func TestServerMessageFactsEditVisibilityAndClearHistory(t *testing.T) {
	f := newServerFacts(t)
	f.msg("3001", 10, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space"})
	before := curVersion("3001", f)
	require.Equal(t, "x0_0", before)

	// Edit changes the native version: the old reference is no longer version exact
	// and the digest follows the edited content.
	f.exec("INSERT INTO message_extra VALUES('3001',7,0,0,'EDITED','abc123')")
	edited := f.resolve("admit", ServerDeliveryReference(1, f.dmChan, "3001", before))[0]
	require.Equal(t, "resolved", edited.Status)
	require.False(t, edited.MessageVersionExact)
	require.Equal(t, "x7_abc123", edited.Header.NativeMessageVersion)
	sum := sha256.Sum256([]byte("EDITED"))
	require.Equal(t, hex.EncodeToString(sum[:]), edited.Header.PayloadSHA256)
	fresh := f.resolve("admit", ServerDeliveryReference(1, f.dmChan, "3001", "x7_abc123"))[0]
	require.True(t, fresh.MessageVersionExact)

	// visibles whitelist excluding the bot is a definite write-time false.
	f.msg("3002", 11, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space", "visibles": []string{"peer"}})
	vis := f.resolve("admit", ServerDeliveryReference(1, f.dmChan, "3002", "x0_0"))[0]
	require.True(t, vis.CallerOriginalVisible)
	require.False(t, vis.BotOriginalVisible)
	require.False(t, vis.BotCurrentRead)

	// Per-user delete and clear-history offset revoke current read but not identity.
	f.msg("3003", 12, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space"})
	f.exec("INSERT INTO message_user_extra VALUES('bot','3003',1)")
	ud := f.resolve("admit", ServerDeliveryReference(1, f.dmChan, "3003", "x0_0"))[0]
	require.False(t, ud.BotCurrentRead)
	require.True(t, ud.CallerCurrentRead)
	f.msg("3004", 13, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space"})
	f.exec("INSERT INTO channel_offset VALUES('peer','bot',1,13)") // DM offsets are keyed by the bare peer uid
	co := f.resolve("admit", ServerDeliveryReference(1, f.dmChan, "3004", "x0_0"))[0]
	require.False(t, co.CallerCurrentRead)
	require.True(t, co.BotCurrentRead)
	f.exec("INSERT INTO channel_setting VALUES(?,1,13)", f.dmChan)
	require.False(t, f.resolve("admit", ServerDeliveryReference(1, f.dmChan, "3004", "x0_0"))[0].BotCurrentRead)
}

func TestServerMessageFactsGroupAndThreadUnknownOriginalVisibility(t *testing.T) {
	f := newServerFacts(t)
	f.msg("4001", 1, "peer", "group", 2, map[string]any{"type": 1})
	f.msg("4002", 2, "peer", f.threadCh, 5, map[string]any{"type": 1})
	f.msg("4003", 3, "departed", "group", 2, map[string]any{"type": 1})

	g := f.resolve("admit", ServerDeliveryReference(2, "group", "4001", "x0_0"))[0]
	require.Equal(t, "resolved", g.Status)
	require.True(t, g.MessageSpaceExact && g.MessageRecipientExact && g.BotCurrentRead && g.CallerCurrentRead && g.BotCurrentSend)
	// Under octo-server's native current group ACL (joining grants full group history
	// subject to current membership, visibles, per-user delete, and offsets), current
	// group read visibility proves original visibility without a send-time witness.
	require.True(t, g.CallerOriginalVisible)
	require.True(t, g.BotOriginalVisible)
	require.False(t, g.CallerOriginalVisibleUnknown || g.BotOriginalVisibleUnknown)
	require.Equal(t, "", g.unknownReason("admit"))
	require.Equal(t, "", g.unknownReason("contributor"))
	require.Equal(t, "", g.unknownReason("reply"))

	th := f.resolve("contributor", ServerDeliveryReference(5, f.threadCh, "4002", "x0_0"))[0]
	require.Equal(t, "thread", th.Header.Source.Kind)
	require.NotNil(t, th.Header.ParentGroup)
	require.Equal(t, f.parent, *th.Header.ParentGroup)
	require.True(t, th.CallerParentCurrentRead && th.BotParentCurrentRead && th.CallerOriginalVisible && th.BotOriginalVisible)
	require.False(t, th.CallerOriginalVisibleUnknown || th.BotOriginalVisibleUnknown)

	// Departed author: current and original read are false (departure revokes caller read).
	dep := f.resolve("admit", ServerDeliveryReference(2, "group", "4003", "x0_0"))[0]
	require.False(t, dep.CallerCurrentRead)
	require.False(t, dep.CallerOriginalVisible)
	require.True(t, dep.BotCurrentRead)
	require.True(t, dep.BotOriginalVisible)

	// Deleted thread and disbanded/disabled groups are non-serving.
	f.exec("UPDATE thread SET status=3")
	require.Equal(t, "expired_reference", f.resolve("admit", ServerDeliveryReference(5, f.threadCh, "4002", "x0_0"))[0].Reason)
	f.exec("UPDATE `group` SET status=0 WHERE group_no='group'")
	require.Equal(t, "expired_reference", f.resolve("admit", ServerDeliveryReference(2, "group", "4001", "x0_0"))[0].Reason)
}

func TestServerMessageFactsHistoryAndTwoStepDisclosure(t *testing.T) {
	f := newServerFacts(t)
	for i := 1; i <= 5; i++ {
		f.msg(strconv.Itoa(5000+i), i, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space", "content": "BODY" + strconv.Itoa(i)})
	}
	f.exec("INSERT INTO message_extra VALUES('5003',2,1,0,NULL,'')") // revoked
	src := ServerSourceReference(1, f.dmChan)
	p1, err := f.p.ListHistoryHeadersV1(t.Context(), fixtureKey, src, nil, 3)
	require.NoError(t, err)
	require.False(t, p1.End)
	require.NotNil(t, p1.NextCursor)
	require.Len(t, p1.Items, 3)
	require.Equal(t, "5005", p1.Items[0].Header.MessageID)
	require.Equal(t, "unavailable", p1.Items[2].Status, "revoked 5003 must not be listed")
	p2, err := f.p.ListHistoryHeadersV1(t.Context(), fixtureKey, src, p1.NextCursor, 3)
	require.NoError(t, err)
	require.True(t, p2.End)
	require.Len(t, p2.Items, 2)
	raw, _ := json.Marshal(p1)
	require.NotContains(t, string(raw), "BODY")
	_, err = f.p.ListHistoryHeadersV1(t.Context(), fixtureKey, src, nil, 33)
	require.ErrorIs(t, err, ErrUnavailable)

	// Step two: permit only for current, version-exact, provably visible headers.
	h5 := p1.Items[0].Header
	items, _, err := f.p.IssueHistoryDisclosureV1(t.Context(), fixtureKey, "ctx1", "epoch1", []string{h5.HeaderReference, "garbage"})
	require.NoError(t, err)
	require.Equal(t, "resolved", items[0].Status)
	require.NotEmpty(t, items[0].Permit)
	require.Equal(t, h5.PayloadSHA256, items[0].PayloadSHA256)
	require.Equal(t, "unavailable", items[1].Status)
	require.NoError(t, f.p.ConsumeDisclosurePermit(fixtureKey, "ctx1", "epoch1", h5.HeaderReference, h5.PayloadSHA256, items[0].Permit))
	require.ErrorIs(t, f.p.ConsumeDisclosurePermit(fixtureKey, "ctx1", "epoch1", h5.HeaderReference, h5.PayloadSHA256, items[0].Permit), ErrReference, "one use")
	require.ErrorIs(t, f.p.ConsumeDisclosurePermit(fixtureKey, "ctx2", "epoch1", h5.HeaderReference, h5.PayloadSHA256, items[0].Permit), ErrReference, "bound to context")

	// Edit after listing: the header reference is stale; no permit is issued.
	f.exec("INSERT INTO message_extra VALUES('5005',9,0,0,'EDITED','h1')")
	stale, _, err := f.p.IssueHistoryDisclosureV1(t.Context(), fixtureKey, "ctx1", "epoch1", []string{h5.HeaderReference})
	require.NoError(t, err)
	require.Equal(t, "unavailable", stale[0].Status)
	require.Empty(t, stale[0].Permit)
	// Revocation after listing also withdraws it.
	f.exec("INSERT INTO message_extra VALUES('5004',3,1,0,NULL,'')")
	gone, _, err := f.p.IssueHistoryDisclosureV1(t.Context(), fixtureKey, "ctx1", "epoch1", []string{p1.Items[1].Header.HeaderReference})
	require.NoError(t, err)
	require.Equal(t, "unavailable", gone[0].Status)

	// Group history is disclosed when current native group ACL allows both caller and bot read,
	// and refused once current group ACL is lost (e.g., channel_offset history cutoff or removal).
	f.msg("5100", 1, "peer", "group", 2, map[string]any{"type": 1})
	gp, err := f.p.ListHistoryHeadersV1(t.Context(), fixtureKey, ServerSourceReference(2, "group"), nil, 2)
	require.NoError(t, err)
	require.Equal(t, "resolved", gp.Items[0].Status)
	gd, _, err := f.p.IssueHistoryDisclosureV1(t.Context(), fixtureKey, "ctx1", "epoch1", []string{gp.Items[0].Header.HeaderReference})
	require.NoError(t, err)
	require.Equal(t, "resolved", gd[0].Status)
	require.NotEmpty(t, gd[0].Permit)
	require.NoError(t, f.p.ConsumeDisclosurePermit(fixtureKey, "ctx1", "epoch1", gp.Items[0].Header.HeaderReference, gp.Items[0].Header.PayloadSHA256, gd[0].Permit))

	f.exec("INSERT INTO channel_offset VALUES('bot','group',2,1)")
	gdHidden, _, err := f.p.IssueHistoryDisclosureV1(t.Context(), fixtureKey, "ctx2", "epoch1", []string{gp.Items[0].Header.HeaderReference})
	require.NoError(t, err)
	require.Equal(t, "unavailable", gdHidden[0].Status)
	require.Equal(t, "disclosure_unavailable", gdHidden[0].Reason)
}

func TestServerMessageFactsConfigAndModeGuards(t *testing.T) {
	s := fixtureStore(t, filepath.Join(t.TempDir(), "guards.sqlite"))
	_, err := NewServerMessageFactProvider(ServerMessageFactConfig{Session: s.Session, Hooks: testServerHooks(), StoreIncarnation: "short", PermitKey: []byte(strings.Repeat("k", 32))})
	require.ErrorIs(t, err, ErrUnavailable)
	_, err = NewServerMessageFactProvider(ServerMessageFactConfig{Session: s.Session, StoreIncarnation: strings.Repeat("5", 32), PermitKey: []byte(strings.Repeat("k", 32))})
	require.ErrorIs(t, err, ErrUnavailable, "shared server hooks are mandatory; no divergent defaults")
	_, err = NewServerMessageFactProvider(ServerMessageFactConfig{Session: s.Session, Hooks: testServerHooks(), StoreIncarnation: strings.Repeat("5", 32), PermitKey: []byte("short")})
	require.ErrorIs(t, err, ErrUnavailable)

	require.NoError(t, RejectPlainMessageSyncFactSource(NativeFactProviderModeServerStoreV1))
	require.ErrorIs(t, RejectPlainMessageSyncFactSource("plain_message_sync"), ErrUnavailable)
	require.ErrorIs(t, RejectPlainMessageSyncFactSource("sql_message_mirror"), ErrUnavailable)

	f := newServerFacts(t)
	_, _, err = f.p.InspectDeliveredHeadersV1(t.Context(), fixtureKey, "bogus", nil)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Error(t, f.p.ValidateIMCut(t.Context(), fixtureKey, "other", strings.Repeat("5", 32), "1", strings.Repeat("a", 32)))
	require.Error(t, f.p.ValidateIMCut(t.Context(), fixtureKey, f.p.authorityID, strings.Repeat("6", 32), "1", strings.Repeat("a", 32)))
	_ = time.Now
}

func TestServerMessageFactsThroughSQLNativeFactAdapter(t *testing.T) {
	ctx := t.Context()
	driver := newSyntheticExternalAuthorityDriver(fixturePin.Digest)
	authority, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)
	f := newServerFacts(t)
	f.s.Authority = authority
	f.msg("6001", 1, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space", "content": "TOP-SECRET"})
	f.msg("6002", 2, "peer", f.dmChan, 1, map[string]any{"type": 1}) // untagged: unknown DM space
	f.msg("6003", 3, "peer", "group", 2, map[string]any{"type": 1})
	adapter, err := NewSQLNativeFactAdapter(authority, f.p)
	require.NoError(t, err)
	adapter.testNoLocks = true
	c := &config.Context{}
	require.NoError(t, Install(c, f.s, fixturePin, adapter))
	rt := RuntimeFor(c)
	require.NotNil(t, rt)

	refs := []string{
		ServerDeliveryReference(1, f.dmChan, "6001", "x0_0"),
		ServerDeliveryReference(1, f.dmChan, "6002", "x0_0"),
		ServerDeliveryReference(2, "group", "6003", "x0_0"),
		ServerDeliveryReference(1, f.dmChan, "6001", ""),
		ServerDeliveryReference(1, f.dmChan, "6999", "x0_0"),
	}
	for _, tc := range []struct {
		purpose string
		want    []string // status per ref
	}{
		{"admit", []string{"resolved", "unavailable", "resolved", "unavailable", "unavailable"}},
		{"contributor", []string{"resolved", "unavailable", "resolved", "unavailable", "unavailable"}},
		{"reply", []string{"resolved", "unavailable", "resolved", "unavailable", "unavailable"}},
	} {
		list := make([]any, len(refs))
		for i, r := range refs {
			list[i] = map[string]any{"delivery_reference": r}
		}
		req := map[string]any{
			"schema_version": json.Number("1"), "profile_version": json.Number("1"), "request_id": strings.Repeat("b", 32),
			"operation": "resolve", "purpose": tc.purpose, "references": list,
		}
		out, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(req)))
		require.NoError(t, err, tc.purpose)
		require.NotContains(t, string(out), "TOP-SECRET")
		results := fixtureObject(t, out)["results"].([]any)
		require.Len(t, results, len(refs))
		for i, want := range tc.want {
			require.Equal(t, want, results[i].(map[string]any)["status"], "%s ref %d", tc.purpose, i)
		}
		if tc.purpose == "admit" {
			preds := results[0].(map[string]any)["predicates"].(map[string]any)
			require.Equal(t, true, preds["message_version_exact"])
			require.Equal(t, true, preds["bot_original_visible"])
			grpPreds := results[2].(map[string]any)["predicates"].(map[string]any)
			require.Equal(t, true, grpPreds["caller_group_active_member"])
			require.Equal(t, true, grpPreds["bot_group_active_member"])
			require.Equal(t, true, grpPreds["caller_current_read"])
			require.Equal(t, true, grpPreds["bot_current_read"])
			require.Equal(t, true, grpPreds["caller_original_visible"])
			require.Equal(t, true, grpPreds["bot_original_visible"])
			require.Equal(t, "predicate_unsupported", results[1].(map[string]any)["reason"])
			require.Equal(t, "mirror_lag", results[4].(map[string]any)["reason"])
		}
	}
}

func sha256OfJSON(v map[string]any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestServerMessageFactsNativeDMBindingChannelIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, channel, from, reason string
	}{
		{name: "peer", channel: "peer", from: "peer"},
		{name: "canonical pair", channel: "canonical", from: "peer"},
		{name: "wrong sender", channel: "peer", from: "departed", reason: "identity_mismatch"},
		{name: "unrelated peer", channel: "departed", from: "peer", reason: "mirror_lag"},
		{name: "self", channel: "bot", from: "peer", reason: "predicate_unsupported"},
		{name: "ambiguous pair", channel: "bot@peer@other", from: "peer", reason: "predicate_unsupported"},
		{name: "unrelated pair", channel: "other@peer", from: "peer", reason: "predicate_unsupported"},
		{name: "noncanonical pair", channel: "reversed", from: "peer", reason: "predicate_unsupported"},
		{name: "space-prefixed peer", channel: "s" + strings.Repeat("a", 32) + "_peer", from: "peer", reason: "mirror_lag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newServerFacts(t)
			payload := map[string]any{"type": 1, "space_id": "space", "content": "NATIVE-DM-SECRET"}
			f.msg("2123243234824982528", 4, "peer", f.dmChan, 1, payload)
			channel := tc.channel
			if channel == "canonical" {
				channel = f.dmChan
			} else if channel == "reversed" {
				parts := strings.Split(f.dmChan, "@")
				channel = parts[1] + "@" + parts[0]
			}
			req := DeliveryBindingRequestV1{ChannelType: 1, ChannelID: channel, MessageID: "2123243234824982528", MessageSeq: "4", FromUID: tc.from, ObservedPayloadSHA256: sha256OfJSON(payload)}
			got, _, err := f.p.BindDeliveredMessageV1(t.Context(), fixtureKey, req)
			require.NoError(t, err)
			if tc.reason != "" {
				require.Equal(t, "refused", got.Status)
				require.Equal(t, tc.reason, got.Reason)
				require.False(t, got.Current)
				require.Empty(t, got.DeliveryReference)
				return
			}
			require.Equal(t, "bound", got.Status)
			require.Equal(t, f.dmChan, got.Header.Source.ID)
			require.Equal(t, ServerDeliveryReference(1, f.dmChan, req.MessageID, "x0_0"), got.DeliveryReference)
			require.Equal(t, []string{"admit", "contributor", "reply"}, got.ResolvablePurposes)
			require.Empty(t, got.UnknownPredicates)
			require.NotContains(t, string(canonical(got.Header.toMap())), "NATIVE-DM-SECRET")
			require.Equal(t, "resolved", f.resolve("admit", got.DeliveryReference)[0].Status)

			req.MessageID = "2123243234824982529"
			missing, _, err := f.p.BindDeliveredMessageV1(t.Context(), fixtureKey, req)
			require.NoError(t, err)
			require.Equal(t, "refused", missing.Status)
			require.Equal(t, "mirror_lag", missing.Reason)

			req.MessageID = "2123243234824982528"
			otherKey := fixtureKey
			otherKey.SpaceID = "other-space"
			wrongSpace, _, err := f.p.BindDeliveredMessageV1(t.Context(), otherKey, req)
			require.NoError(t, err)
			require.Equal(t, "refused", wrongSpace.Status)
			require.Equal(t, "visibility_denied", wrongSpace.Reason)

			f.exec("INSERT INTO message_user_extra VALUES('bot',?,1)", req.MessageID)
			hidden, _, err := f.p.BindDeliveredMessageV1(t.Context(), fixtureKey, req)
			require.NoError(t, err)
			require.Equal(t, "refused", hidden.Status)
			require.Equal(t, "visibility_denied", hidden.Reason)
		})
	}
}

func TestServerMessageFactsNativeGroupBindingRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, mutation, reason string
	}{
		{name: "current"},
		{name: "missing", mutation: "DELETE FROM message", reason: "mirror_lag"},
		{name: "wrong space", mutation: "UPDATE `group` SET space_id='other-space'", reason: "visibility_denied"},
		{name: "removed bot", mutation: "UPDATE group_member SET is_deleted=1 WHERE uid='bot'", reason: "visibility_denied"},
		{name: "blocked bot", mutation: "UPDATE group_member SET status=0 WHERE uid='bot'", reason: "visibility_denied"},
		{name: "removed caller", mutation: "UPDATE group_member SET is_deleted=1 WHERE uid='peer'", reason: "visibility_denied"},
		{name: "blocked caller", mutation: "UPDATE group_member SET status=0 WHERE uid='peer'", reason: "visibility_denied"},
		{name: "bot clear history offset", mutation: "INSERT INTO channel_offset VALUES('bot','group',2,3)", reason: "visibility_denied"},
		{name: "caller clear history offset", mutation: "INSERT INTO channel_offset VALUES('peer','group',2,3)", reason: "visibility_denied"},
		{name: "channel setting offset", mutation: "INSERT INTO channel_setting VALUES('group',2,3)", reason: "visibility_denied"},
		{name: "bot user extra deleted", mutation: "INSERT INTO message_user_extra VALUES('bot','2123243248167063552',1)", reason: "visibility_denied"},
		{name: "caller user extra deleted", mutation: "INSERT INTO message_user_extra VALUES('peer','2123243248167063552',1)", reason: "visibility_denied"},
		{name: "revoked", mutation: "INSERT INTO message_extra VALUES('2123243248167063552',1,1,0,NULL,'')", reason: "expired_reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newServerFacts(t)
			payload := map[string]any{"type": 1, "content": "NATIVE-GROUP-SECRET"}
			f.msg("2123243248167063552", 3, "peer", "group", 2, payload)
			if tc.mutation != "" {
				f.exec(tc.mutation)
			}
			req := DeliveryBindingRequestV1{ChannelType: 2, ChannelID: "group", MessageID: "2123243248167063552", MessageSeq: "3", FromUID: "peer", ObservedPayloadSHA256: sha256OfJSON(payload)}
			got, _, err := f.p.BindDeliveredMessageV1(t.Context(), fixtureKey, req)
			require.NoError(t, err)
			if tc.reason != "" {
				require.Equal(t, "refused", got.Status)
				require.Equal(t, tc.reason, got.Reason)
				require.False(t, got.Current)
				return
			}
			require.Equal(t, "bound", got.Status)
			require.Equal(t, []string{"admit", "contributor", "reply"}, got.ResolvablePurposes)
			require.Empty(t, got.UnknownPredicates)
			require.Equal(t, true, got.ProvenPredicates["caller_original_visible"])
			require.Equal(t, true, got.ProvenPredicates["bot_original_visible"])
			require.NotContains(t, string(canonical(got.Header.toMap())), "NATIVE-GROUP-SECRET")
		})
	}
}

func TestServerMessageFactsMySQLExtraQuery(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	conn := &dbr.Connection{DB: db, EventReceiver: &dbr.NullEventReceiver{}, Dialect: dialect.MySQL}
	p := &ServerMessageFactProvider{db: conn.NewSession(nil)}
	query := "SELECT COALESCE(version,0),COALESCE(`revoke`,0),COALESCE(is_deleted,0),content_edit,COALESCE(content_edit_hash,'') FROM message_extra WHERE message_id=?"
	mock.ExpectQuery(query).WithArgs("2123243248167063552").WillReturnError(sql.ErrNoRows)
	extra, err := p.loadExtra(t.Context(), "2123243248167063552")
	require.NoError(t, err)
	require.False(t, extra.exists)
	mock.ExpectQuery(query).WithArgs("2123243248167063552").WillReturnRows(sqlmock.NewRows([]string{"version", "revoke", "is_deleted", "content_edit", "content_edit_hash"}).AddRow(2, 1, 0, nil, ""))
	extra, err = p.loadExtra(t.Context(), "2123243248167063552")
	require.NoError(t, err)
	require.True(t, extra.exists)
	require.Equal(t, 1, extra.revoke)
	require.NoError(t, mock.ExpectationsWereMet())
	mock.ExpectClose()
}

func TestServerMessageFactsBindDeliveredMessagePositiveAndRaceRefusals(t *testing.T) {
	ctx := t.Context()
	driver := newSyntheticExternalAuthorityDriver(fixturePin.Digest)
	authority, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)
	f := newServerFacts(t)
	f.s.Authority = authority

	dmPayload := map[string]any{"type": 1, "space_id": "space", "content": "DM-SECRET-BODY"}
	dmDigest := sha256OfJSON(dmPayload)
	f.msg("7001", 1, "peer", f.dmChan, 1, dmPayload)

	groupPayload := map[string]any{"type": 1, "content": "GROUP-SECRET-BODY"}
	groupDigest := sha256OfJSON(groupPayload)
	f.msg("7002", 2, "peer", "group", 2, groupPayload)

	threadPayload := map[string]any{"type": 1, "content": "THREAD-SECRET-BODY"}
	threadDigest := sha256OfJSON(threadPayload)
	f.msg("7003", 3, "peer", f.threadCh, 5, threadPayload)

	untaggedDMPayload := map[string]any{"type": 1, "content": "UNTAGGED-DM-SECRET"}
	untaggedDMDigest := sha256OfJSON(untaggedDMPayload)
	f.msg("7004", 4, "peer", f.dmChan, 1, untaggedDMPayload)

	crossSpaceDMPayload := map[string]any{"type": 1, "space_id": "other-space", "content": "CROSS-SPACE-SECRET"}
	crossSpaceDMDigest := sha256OfJSON(crossSpaceDMPayload)
	f.msg("7005", 5, "peer", f.dmChan, 1, crossSpaceDMPayload)

	adapter, err := NewSQLNativeFactAdapter(authority, f.p)
	require.NoError(t, err)
	adapter.testNoLocks = true
	c := &config.Context{}
	require.NoError(t, Install(c, f.s, fixturePin, adapter))
	rt := RuntimeFor(c)
	require.NotNil(t, rt)
	require.True(t, rt.HasDeliveryBinding())

	callBind := func(req map[string]any) map[string]any {
		out, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(req)))
		require.NoError(t, err)
		for _, secret := range []string{"DM-SECRET-BODY", "GROUP-SECRET-BODY", "THREAD-SECRET-BODY", "UNTAGGED-DM-SECRET", "CROSS-SPACE-SECRET", "EDITED-BODY"} {
			require.NotContains(t, string(out), secret)
		}
		return fixtureObject(t, out)["binding"].(map[string]any)
	}

	// 1. Positive path: space-tagged DM binds with all purposes resolvable and zero unknowns.
	bDM := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-dm-1",
		"channel_type":            json.Number("1"),
		"channel_id":              "peer",
		"message_id":              "7001",
		"message_seq":             "1",
		"from_uid":                "peer",
		"observed_payload_sha256": dmDigest,
	})
	require.Equal(t, "bound", bDM["status"])
	require.Equal(t, true, bDM["current"])
	require.Equal(t, "x0_0", bDM["native_message_version"])
	require.Equal(t, ServerDeliveryReference(1, f.dmChan, "7001", "x0_0"), bDM["delivery_reference"])
	require.Empty(t, bDM["unknown_predicates"].([]any))
	require.Equal(t, []any{"admit", "contributor", "reply"}, bDM["resolvable_purposes"].([]any))

	// 2. Positive path: Group and Thread bind for admit, contributor, and reply under
	// native current group/thread ACL with zero unknown_predicates.
	bGroup := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-grp-1",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"message_id":              "7002",
		"message_seq":             "2",
		"from_uid":                "peer",
		"observed_payload_sha256": groupDigest,
	})
	require.Equal(t, "bound", bGroup["status"])
	require.Empty(t, bGroup["unknown_predicates"].([]any))
	require.Equal(t, []any{"admit", "contributor", "reply"}, bGroup["resolvable_purposes"].([]any))
	grpProven := bGroup["proven_predicates"].(map[string]any)
	require.Equal(t, true, grpProven["caller_original_visible"])
	require.Equal(t, true, grpProven["bot_original_visible"])

	bThread := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-thd-1",
		"channel_type":            json.Number("5"),
		"channel_id":              f.threadCh,
		"message_id":              "7003",
		"message_seq":             "3",
		"from_uid":                "peer",
		"observed_payload_sha256": threadDigest,
	})
	require.Equal(t, "bound", bThread["status"])
	require.Empty(t, bThread["unknown_predicates"].([]any))
	require.Equal(t, []any{"admit", "contributor", "reply"}, bThread["resolvable_purposes"].([]any))
	thdProven := bThread["proven_predicates"].(map[string]any)
	require.Equal(t, true, thdProven["caller_original_visible"])
	require.Equal(t, true, thdProven["bot_original_visible"])

	// 3. Untagged DM binds reference metadata but marks message_space_exact as unknown (non-serving for resolve).
	bUntagged := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-untagged-1",
		"channel_type":            json.Number("1"),
		"channel_id":              f.dmChan,
		"message_id":              "7004",
		"message_seq":             "4",
		"from_uid":                "peer",
		"observed_payload_sha256": untaggedDMDigest,
	})
	require.Equal(t, "bound", bUntagged["status"])
	require.Equal(t, []any{"message_space_exact"}, bUntagged["unknown_predicates"].([]any))
	require.Empty(t, bUntagged["resolvable_purposes"].([]any))
	require.NotContains(t, bUntagged["proven_predicates"].(map[string]any), "message_space_exact")

	// 4. Race/mismatch negative path: concurrent edit in message_extra changes effective payload digest.
	// A current-version lookup alone cannot prove the pre-edit frame's version, so binding with the
	// pre-edit observed_payload_sha256 explicitly refuses with payload_digest_mismatch.
	editedBytes := `{"content":"EDITED-BODY","space_id":"space","type":1}`
	editedSum := sha256.Sum256([]byte(editedBytes))
	editedDigest := hex.EncodeToString(editedSum[:])
	f.exec("INSERT INTO message_extra VALUES('7001',4,0,0,?,'e44')", editedBytes)

	bRace := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-race-1",
		"channel_type":            json.Number("1"),
		"channel_id":              f.dmChan,
		"message_id":              "7001",
		"message_seq":             "1",
		"from_uid":                "peer",
		"observed_payload_sha256": dmDigest,
	})
	require.Equal(t, "refused", bRace["status"])
	require.Equal(t, "payload_digest_mismatch", bRace["reason"])
	require.Equal(t, false, bRace["current"])
	require.Equal(t, "x4_e44", bRace["native_message_version"])

	// Stale expected_native_version also refuses with version_mismatch even if digest matches edited payload.
	bStaleVer := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-ver-1",
		"channel_type":            json.Number("1"),
		"channel_id":              f.dmChan,
		"message_id":              "7001",
		"message_seq":             "1",
		"from_uid":                "peer",
		"observed_payload_sha256": editedDigest,
		"expected_native_version": "x0_0",
	})
	require.Equal(t, "refused", bStaleVer["status"])
	require.Equal(t, "version_mismatch", bStaleVer["reason"])
	require.Equal(t, "x4_e44", bStaleVer["native_message_version"])

	// Matching edited digest and expected_native_version binds to x4_e44.
	bEditedOK := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-edited-ok",
		"channel_type":            json.Number("1"),
		"channel_id":              f.dmChan,
		"message_id":              "7001",
		"message_seq":             "1",
		"from_uid":                "peer",
		"observed_payload_sha256": editedDigest,
		"expected_native_version": "x4_e44",
	})
	require.Equal(t, "bound", bEditedOK["status"])
	require.Equal(t, ServerDeliveryReference(1, f.dmChan, "7001", "x4_e44"), bEditedOK["delivery_reference"])

	// 5. Sender or sequence mismatch refuses with identity_mismatch.
	bBadSender := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-sender-bad",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"message_id":              "7002",
		"message_seq":             "2",
		"from_uid":                "departed",
		"observed_payload_sha256": groupDigest,
	})
	require.Equal(t, "refused", bBadSender["status"])
	require.Equal(t, "identity_mismatch", bBadSender["reason"])

	bBadSeq := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-seq-bad",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"message_id":              "7002",
		"message_seq":             "99",
		"from_uid":                "peer",
		"observed_payload_sha256": groupDigest,
	})
	require.Equal(t, "refused", bBadSeq["status"])
	require.Equal(t, "identity_mismatch", bBadSeq["reason"])

	// 6. Revoked, missing, and cross-space messages refuse with exact reasons.
	f.exec("UPDATE message_extra SET revoke=1 WHERE message_id='7001'")
	bRevoked := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-revoked",
		"channel_type":            json.Number("1"),
		"channel_id":              f.dmChan,
		"message_id":              "7001",
		"message_seq":             "1",
		"from_uid":                "peer",
		"observed_payload_sha256": editedDigest,
	})
	require.Equal(t, "refused", bRevoked["status"])
	require.Equal(t, "expired_reference", bRevoked["reason"])

	bMissing := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-missing",
		"channel_type":            json.Number("1"),
		"channel_id":              f.dmChan,
		"message_id":              "7999",
		"message_seq":             "99",
		"from_uid":                "peer",
		"observed_payload_sha256": dmDigest,
	})
	require.Equal(t, "refused", bMissing["status"])
	require.Equal(t, "mirror_lag", bMissing["reason"])

	bCrossSpace := callBind(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "req-bind-cross-space",
		"channel_type":            json.Number("1"),
		"channel_id":              f.dmChan,
		"message_id":              "7005",
		"message_seq":             "5",
		"from_uid":                "peer",
		"observed_payload_sha256": crossSpaceDMDigest,
	})
	require.Equal(t, "refused", bCrossSpace["status"])
	require.Equal(t, "visibility_denied", bCrossSpace["reason"])
}

func TestServerMessageFactsDurablePermitLedgerSurvivesRestart(t *testing.T) {
	f := newServerFacts(t)
	f.exec(ServerDisclosurePermitDDL)

	p1, err := NewServerMessageFactProvider(ServerMessageFactConfig{
		Session:             f.s.Session,
		Hooks:               testServerHooks(),
		StoreIncarnation:    strings.Repeat("5", 32),
		PermitKey:           []byte(strings.Repeat("k", 32)),
		DurablePermitLedger: true,
	})
	require.NoError(t, err)

	f.msg("8001", 1, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space", "content": "PERMIT-BODY"})
	src := ServerSourceReference(1, f.dmChan)
	page, err := p1.ListHistoryHeadersV1(t.Context(), fixtureKey, src, nil, 2)
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	hdr := page.Items[0].Header

	items, _, err := p1.IssueHistoryDisclosureV1(t.Context(), fixtureKey, "ctx-durable", "1", []string{hdr.HeaderReference})
	require.NoError(t, err)
	require.Equal(t, "resolved", items[0].Status)
	permit := items[0].Permit
	require.NotEmpty(t, permit)

	// Consume the permit once in process 1.
	require.NoError(t, p1.ConsumeDisclosurePermit(fixtureKey, "ctx-durable", "1", hdr.HeaderReference, hdr.PayloadSHA256, permit))

	// Simulate a process restart by constructing a brand-new provider instance
	// with a fresh in-memory map against the same SQLite database.
	p2, err := NewServerMessageFactProvider(ServerMessageFactConfig{
		Session:             f.s.Session,
		Hooks:               testServerHooks(),
		StoreIncarnation:    strings.Repeat("5", 32),
		PermitKey:           []byte(strings.Repeat("k", 32)),
		DurablePermitLedger: true,
	})
	require.NoError(t, err)

	// Replaying the consumed permit after restart is rejected by the SQL permit ledger.
	require.ErrorIs(t, p2.ConsumeDisclosurePermit(fixtureKey, "ctx-durable", "1", hdr.HeaderReference, hdr.PayloadSHA256, permit), ErrReference)

	// Re-requesting IssueHistoryDisclosureV1 for the already-consumed (context, epoch, headerRef)
	// after restart refuses to resurrect the consumed permit.
	reissue, _, err := p2.IssueHistoryDisclosureV1(t.Context(), fixtureKey, "ctx-durable", "1", []string{hdr.HeaderReference})
	require.NoError(t, err)
	require.Equal(t, "unavailable", reissue[0].Status)
	require.Equal(t, "disclosure_unavailable", reissue[0].Reason)
}

func TestServerMessageFactsMessageExpireTTLBoundaryAndRevalidation(t *testing.T) {
	ctx := t.Context()
	driver := newSyntheticExternalAuthorityDriver(fixturePin.Digest)
	authority, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)
	f := newServerFacts(t)
	f.s.Authority = authority
	f.exec(ServerDisclosurePermitDDL)
	f.p.durablePermits = true

	// Controllable provider clock starting at t = 1700000100.
	nowUnix := int64(1700000100)
	f.p.now = func() time.Time { return time.Unix(nowUnix, 0).UTC() }

	const baseTS = int64(1700000000)
	p9001 := map[string]any{"type": 1, "space_id": "space", "content": "TTL-LIVE-NO-EXPIRE"}
	p9002 := map[string]any{"type": 1, "space_id": "space", "content": "TTL-UNEXPIRED-101"}
	p9003 := map[string]any{"type": 1, "space_id": "space", "content": "TTL-AT-BOUNDARY-100"}
	p9004 := map[string]any{"type": 1, "space_id": "space", "content": "TTL-PAST-BOUNDARY-50"}
	p9005 := map[string]any{"type": 1, "space_id": "space", "content": "TTL-REVALIDATE-105"}
	p9006 := map[string]any{"type": 1, "content": "TTL-GROUP-BOUNDARY-100"}

	// 9001: expire=0 (never expires)
	f.msgWithExpire("9001", 1, "peer", f.dmChan, 1, baseTS, 0, p9001)
	// 9002: expire=101 -> at now=1700000100, now - expire = 1699999999 < baseTS (unexpired)
	f.msgWithExpire("9002", 2, "peer", f.dmChan, 1, baseTS, 101, p9002)
	// 9003: expire=100 -> at now=1700000100, now - expire = 1700000000 == baseTS (expired at boundary)
	f.msgWithExpire("9003", 3, "peer", f.dmChan, 1, baseTS, 100, p9003)
	// 9004: expire=50 -> at now=1700000100, now - expire = 1700000050 > baseTS (expired past boundary)
	f.msgWithExpire("9004", 4, "peer", f.dmChan, 1, baseTS, 50, p9004)
	// 9005: expire=105 -> unexpired at now=1700000100, expires when clock advances to 1700000105
	f.msgWithExpire("9005", 5, "peer", f.dmChan, 1, baseTS, 105, p9005)
	// 9006: group message at boundary (expire=100)
	f.msgWithExpire("9006", 1, "peer", "group", 2, baseTS, 100, p9006)

	// Provision scope so Runtime.Facts(history_disclosure) can validate context_epoch ("0").
	_, err = f.s.Get(ctx, fixtureKey, "owner")
	require.NoError(t, err)

	adapter, err := NewSQLNativeFactAdapter(authority, f.p)
	require.NoError(t, err)
	adapter.testNoLocks = true
	c := &config.Context{}
	require.NoError(t, Install(c, f.s, fixturePin, adapter))
	rt := RuntimeFor(c)
	require.NotNil(t, rt)

	assertNoSecrets := func(out []byte) {
		for _, s := range []string{
			"TTL-LIVE-NO-EXPIRE", "TTL-UNEXPIRED-101", "TTL-AT-BOUNDARY-100",
			"TTL-PAST-BOUNDARY-50", "TTL-REVALIDATE-105", "TTL-GROUP-BOUNDARY-100",
		} {
			require.NotContains(t, string(out), s)
		}
	}

	callBind := func(reqID string, ctype int, ch, msgID, seq string, payload map[string]any) map[string]any {
		out, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
			"schema_version":          json.Number("1"),
			"operation":               "bind_delivery",
			"request_id":              reqID,
			"channel_type":            json.Number(strconv.Itoa(ctype)),
			"channel_id":              ch,
			"message_id":              msgID,
			"message_seq":             seq,
			"from_uid":                "peer",
			"observed_payload_sha256": sha256OfJSON(payload),
		})))
		require.NoError(t, err)
		assertNoSecrets(out)
		return fixtureObject(t, out)["binding"].(map[string]any)
	}

	// 1. BindDeliveredMessage at now = 1700000100:
	b9001 := callBind("req-ttl-bind-9001", 1, f.dmChan, "9001", "1", p9001)
	require.Equal(t, "bound", b9001["status"])
	require.Equal(t, true, b9001["current"])

	b9002 := callBind("req-ttl-bind-9002", 1, f.dmChan, "9002", "2", p9002)
	require.Equal(t, "bound", b9002["status"])
	require.Equal(t, true, b9002["current"])

	b9003 := callBind("req-ttl-bind-9003", 1, f.dmChan, "9003", "3", p9003)
	require.Equal(t, "refused", b9003["status"])
	require.Equal(t, "expired_reference", b9003["reason"])
	require.Equal(t, false, b9003["current"])

	b9004 := callBind("req-ttl-bind-9004", 1, f.dmChan, "9004", "4", p9004)
	require.Equal(t, "refused", b9004["status"])
	require.Equal(t, "expired_reference", b9004["reason"])
	require.Equal(t, false, b9004["current"])

	b9005 := callBind("req-ttl-bind-9005", 1, f.dmChan, "9005", "5", p9005)
	require.Equal(t, "bound", b9005["status"])
	require.Equal(t, true, b9005["current"])
	ref9005 := b9005["delivery_reference"].(string)
	hdrRef9005 := b9005["header_reference"].(string)

	b9006 := callBind("req-ttl-bind-9006", 2, "group", "9006", "1", p9006)
	require.Equal(t, "refused", b9006["status"])
	require.Equal(t, "expired_reference", b9006["reason"])
	require.Equal(t, false, b9006["current"])

	// 2. Resolve via Runtime.Facts at now = 1700000100:
	ref9001 := ServerDeliveryReference(1, f.dmChan, "9001", "x0_0")
	ref9002 := ServerDeliveryReference(1, f.dmChan, "9002", "x0_0")
	ref9003 := ServerDeliveryReference(1, f.dmChan, "9003", "x0_0")
	ref9004 := ServerDeliveryReference(1, f.dmChan, "9004", "x0_0")
	ref9006 := ServerDeliveryReference(2, "group", "9006", "x0_0")

	for _, purpose := range []string{"admit", "contributor", "reply"} {
		resBytes, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
			"schema_version":  json.Number("1"),
			"profile_version": json.Number("1"),
			"request_id":      hex.EncodeToString([]byte("ttl-res-" + purpose + "----------------")[:16]),
			"operation":       "resolve",
			"purpose":         purpose,
			"references": []any{
				map[string]any{"delivery_reference": ref9001},
				map[string]any{"delivery_reference": ref9002},
				map[string]any{"delivery_reference": ref9003},
				map[string]any{"delivery_reference": ref9004},
				map[string]any{"delivery_reference": ref9005},
				map[string]any{"delivery_reference": ref9006},
			},
		})))
		require.NoError(t, err)
		assertNoSecrets(resBytes)
		results := fixtureObject(t, resBytes)["results"].([]any)
		require.Len(t, results, 6)
		require.Equal(t, "resolved", results[0].(map[string]any)["status"])
		require.Equal(t, "resolved", results[1].(map[string]any)["status"])
		require.Equal(t, "unavailable", results[2].(map[string]any)["status"])
		require.Equal(t, "expired_reference", results[2].(map[string]any)["reason"])
		require.Equal(t, "unavailable", results[3].(map[string]any)["status"])
		require.Equal(t, "expired_reference", results[3].(map[string]any)["reason"])
		require.Equal(t, "resolved", results[4].(map[string]any)["status"])
		require.Equal(t, "unavailable", results[5].(map[string]any)["status"])
		require.Equal(t, "expired_reference", results[5].(map[string]any)["reason"])
	}

	// 3. History headers via Runtime.Facts at now = 1700000100:
	// Ordered newest first: 9005 (resolved), 9004 (unavailable/expired_reference),
	// 9003 (unavailable/expired_reference), 9002 (resolved), 9001 (resolved).
	hhBytes, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":   json.Number("1"),
		"profile_version":  json.Number("1"),
		"request_id":       strings.Repeat("a", 32),
		"operation":        "history_headers",
		"source_reference": ServerSourceReference(1, f.dmChan),
		"cursor":           nil,
		"page_size":        json.Number("10"),
	})))
	require.NoError(t, err)
	assertNoSecrets(hhBytes)
	hhItems := fixtureObject(t, hhBytes)["page"].(map[string]any)["items"].([]any)
	require.Len(t, hhItems, 5)
	require.Equal(t, "9005", hhItems[0].(map[string]any)["message_id"])
	require.Equal(t, "unavailable", hhItems[1].(map[string]any)["status"])
	require.Equal(t, "expired_reference", hhItems[1].(map[string]any)["reason"])
	require.Equal(t, "unavailable", hhItems[2].(map[string]any)["status"])
	require.Equal(t, "expired_reference", hhItems[2].(map[string]any)["reason"])
	require.Equal(t, "9002", hhItems[3].(map[string]any)["message_id"])
	require.Equal(t, "9001", hhItems[4].(map[string]any)["message_id"])

	hdrRef9001 := hhItems[4].(map[string]any)["header_reference"].(string)
	hdrRef9002 := hhItems[3].(map[string]any)["header_reference"].(string)
	hdrRef9003 := encodeServerRef(serverRefHeader, serverRef{channelType: 1, channelID: f.dmChan, messageID: "9003", version: "x0_0"})
	hdrRef9004 := encodeServerRef(serverRefHeader, serverRef{channelType: 1, channelID: f.dmChan, messageID: "9004", version: "x0_0"})

	// 4. History disclosure via Runtime.Facts at now = 1700000100:
	// 9001 and 9002 receive permits; 9003 (at boundary) and 9004 (past boundary) are refused with expired_reference and zero permit.
	hdBytes, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("b", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("c", 32),
		"context_epoch":   "0",
		"headers": []any{
			map[string]any{"header_reference": hdrRef9001},
			map[string]any{"header_reference": hdrRef9002},
			map[string]any{"header_reference": hdrRef9003},
			map[string]any{"header_reference": hdrRef9004},
		},
	})))
	require.NoError(t, err)
	assertNoSecrets(hdBytes)
	hdResults := fixtureObject(t, hdBytes)["results"].([]any)
	require.Len(t, hdResults, 4)
	require.Equal(t, "resolved", hdResults[0].(map[string]any)["status"])
	require.NotEmpty(t, hdResults[0].(map[string]any)["permit"])
	require.Equal(t, "resolved", hdResults[1].(map[string]any)["status"])
	require.NotEmpty(t, hdResults[1].(map[string]any)["permit"])
	require.Equal(t, "unavailable", hdResults[2].(map[string]any)["status"])
	require.Equal(t, "expired_reference", hdResults[2].(map[string]any)["reason"])
	require.Nil(t, hdResults[2].(map[string]any)["permit"])
	require.Equal(t, "unavailable", hdResults[3].(map[string]any)["status"])
	require.Equal(t, "expired_reference", hdResults[3].(map[string]any)["reason"])
	require.Nil(t, hdResults[3].(map[string]any)["permit"])

	// 5. Revalidation after clock advances to now = 1700000105:
	// 9005 (expire=105) is now at its exact TTL boundary, and 9002 (expire=101) is now past its boundary.
	// Even though 9005 was bound and listed as resolved at t=1700000100, re-resolving or requesting
	// history_disclosure at t=1700000105 must refuse with expired_reference and issue no permit.
	nowUnix = 1700000105

	b9005After := callBind("req-ttl-bind-9005-after", 1, f.dmChan, "9005", "5", p9005)
	require.Equal(t, "refused", b9005After["status"])
	require.Equal(t, "expired_reference", b9005After["reason"])

	resAfterBytes, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("d", 32),
		"operation":       "resolve",
		"purpose":         "contributor",
		"references": []any{
			map[string]any{"delivery_reference": ref9001},
			map[string]any{"delivery_reference": ref9002},
			map[string]any{"delivery_reference": ref9005},
		},
	})))
	require.NoError(t, err)
	resAfter := fixtureObject(t, resAfterBytes)["results"].([]any)
	require.Equal(t, "resolved", resAfter[0].(map[string]any)["status"])
	require.Equal(t, "unavailable", resAfter[1].(map[string]any)["status"])
	require.Equal(t, "expired_reference", resAfter[1].(map[string]any)["reason"])
	require.Equal(t, "unavailable", resAfter[2].(map[string]any)["status"])
	require.Equal(t, "expired_reference", resAfter[2].(map[string]any)["reason"])

	hdAfterBytes, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("e", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("f", 32),
		"context_epoch":   "0",
		"headers": []any{
			map[string]any{"header_reference": hdrRef9005},
			map[string]any{"header_reference": hdrRef9002},
			map[string]any{"header_reference": hdrRef9001},
		},
	})))
	require.NoError(t, err)
	assertNoSecrets(hdAfterBytes)
	hdAfter := fixtureObject(t, hdAfterBytes)["results"].([]any)
	require.Equal(t, "unavailable", hdAfter[0].(map[string]any)["status"])
	require.Equal(t, "expired_reference", hdAfter[0].(map[string]any)["reason"])
	require.Nil(t, hdAfter[0].(map[string]any)["permit"])
	require.Equal(t, "unavailable", hdAfter[1].(map[string]any)["status"])
	require.Equal(t, "expired_reference", hdAfter[1].(map[string]any)["reason"])
	require.Nil(t, hdAfter[1].(map[string]any)["permit"])
	require.Equal(t, "resolved", hdAfter[2].(map[string]any)["status"])
	require.NotEmpty(t, hdAfter[2].(map[string]any)["permit"])

	// Verify durable ledger has zero rows for expired 9003, 9004, or 9005.
	var expiredPermits int
	err = f.s.Session.QueryRow(
		"SELECT COUNT(*) FROM "+ServerDisclosurePermitTable+" WHERE header_reference IN (?,?,?)",
		hdrRef9003, hdrRef9004, hdrRef9005,
	).Scan(&expiredPermits)
	require.NoError(t, err)
	require.Equal(t, 0, expiredPermits)
}

func TestServerMessageFactsRound2CrossSpaceHistoryAndDisclosureScopeAndEpochGuards(t *testing.T) {
	ctx := t.Context()
	driver := newSyntheticExternalAuthorityDriver(fixturePin.Digest)
	authority, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)
	f := newServerFacts(t)
	f.s.Authority = authority
	f.exec(ServerDisclosurePermitDDL)
	f.p.durablePermits = true

	// Provision scope (context_epoch = "0", retired = 0).
	_, err = f.s.Get(ctx, fixtureKey, "owner")
	require.NoError(t, err)

	// Seed DM messages in f.dmChan:
	// 9501: same-space tagged DM ("space") -> resolved
	// 9502: untagged DM (MessageSpaceUnknown == true) -> unavailable (predicate_unsupported)
	// 9503: cross-space tagged DM ("other-space", MessageSpaceExact == false) -> unavailable (expired_reference)
	// 9505: second same-space tagged DM ("space") for [S-B3] scope revocation checks
	f.msg("9501", 1, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space", "content": "R2-SAME-SPACE-DM"})
	f.msg("9502", 2, "peer", f.dmChan, 1, map[string]any{"type": 1, "content": "R2-UNTAGGED-DM"})
	f.msg("9503", 3, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "other-space", "content": "R2-CROSS-SPACE-DM"})
	f.msg("9505", 4, "peer", f.dmChan, 1, map[string]any{"type": 1, "space_id": "space", "content": "R2-SCOPE-GUARD-DM"})

	// Seed a group in space_B ("other-space") where both bot and peer are active members, plus message 9504.
	f.exec("INSERT INTO `group` VALUES('group_space_b','other-space',1)")
	f.exec("INSERT INTO group_member VALUES('group_space_b','bot',1,0,0),('group_space_b','peer',1,0,0)")
	f.msg("9504", 1, "peer", "group_space_b", 2, map[string]any{"type": 1, "content": "R2-CROSS-SPACE-GROUP"})

	adapter, err := NewSQLNativeFactAdapter(authority, f.p)
	require.NoError(t, err)
	adapter.testNoLocks = true
	c := &config.Context{}
	require.NoError(t, Install(c, f.s, fixturePin, adapter))
	rt := RuntimeFor(c)
	require.NotNil(t, rt)

	// [S-B2] Part 1: Direct ListHistoryHeadersV1 and Runtime.Facts(history_headers) on DM channel.
	// Newest first: 9505 (resolved), 9503 (unavailable: cross-space), 9502 (unavailable: untagged DM), 9501 (resolved).
	dmSrc := ServerSourceReference(1, f.dmChan)
	dmPage, err := f.p.ListHistoryHeadersV1(ctx, fixtureKey, dmSrc, nil, 10)
	require.NoError(t, err)
	require.Len(t, dmPage.Items, 4)
	require.Equal(t, "resolved", dmPage.Items[0].Status)
	require.Equal(t, "9505", dmPage.Items[0].Header.MessageID)
	require.Equal(t, "unavailable", dmPage.Items[1].Status, "cross-space DM 9503 must not resolve in history_headers")
	require.Equal(t, "expired_reference", dmPage.Items[1].Reason)
	require.Empty(t, dmPage.Items[1].Header.MessageID)
	require.Equal(t, "unavailable", dmPage.Items[2].Status, "untagged DM 9502 must not resolve in history_headers")
	require.Equal(t, "predicate_unsupported", dmPage.Items[2].Reason)
	require.Empty(t, dmPage.Items[2].Header.MessageID)
	require.Equal(t, "resolved", dmPage.Items[3].Status)
	require.Equal(t, "9501", dmPage.Items[3].Header.MessageID)

	hhDMBytes, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":   json.Number("1"),
		"profile_version":  json.Number("1"),
		"request_id":       strings.Repeat("1", 32),
		"operation":        "history_headers",
		"source_reference": dmSrc,
		"cursor":           nil,
		"page_size":        json.Number("10"),
	})))
	require.NoError(t, err)
	require.NotContains(t, string(hhDMBytes), "other-space")
	hhDMItems := fixtureObject(t, hhDMBytes)["page"].(map[string]any)["items"].([]any)
	require.Len(t, hhDMItems, 4)
	require.Equal(t, "9505", hhDMItems[0].(map[string]any)["message_id"])
	require.Equal(t, "unavailable", hhDMItems[1].(map[string]any)["status"])
	require.Equal(t, "expired_reference", hhDMItems[1].(map[string]any)["reason"])
	require.Equal(t, "unavailable", hhDMItems[2].(map[string]any)["status"])
	require.Equal(t, "predicate_unsupported", hhDMItems[2].(map[string]any)["reason"])
	require.Equal(t, "9501", hhDMItems[3].(map[string]any)["message_id"])

	// [S-B2] Part 2: Cross-space group source_reference queried under fixtureKey (space_id="space").
	grpBSrc := ServerSourceReference(2, "group_space_b")
	grpBPage, err := f.p.ListHistoryHeadersV1(ctx, fixtureKey, grpBSrc, nil, 10)
	require.NoError(t, err)
	require.Len(t, grpBPage.Items, 1)
	require.Equal(t, "unavailable", grpBPage.Items[0].Status, "group in other-space must be unavailable under space")
	require.Equal(t, "expired_reference", grpBPage.Items[0].Reason)
	require.Empty(t, grpBPage.Items[0].Header.MessageID)

	hhGrpBBytes, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":   json.Number("1"),
		"profile_version":  json.Number("1"),
		"request_id":       strings.Repeat("2", 32),
		"operation":        "history_headers",
		"source_reference": grpBSrc,
		"cursor":           nil,
		"page_size":        json.Number("10"),
	})))
	require.NoError(t, err)
	require.NotContains(t, string(hhGrpBBytes), "other-space")
	hhGrpBItems := fixtureObject(t, hhGrpBBytes)["page"].(map[string]any)["items"].([]any)
	require.Len(t, hhGrpBItems, 1)
	require.Equal(t, "unavailable", hhGrpBItems[0].(map[string]any)["status"])
	require.Equal(t, "expired_reference", hhGrpBItems[0].(map[string]any)["reason"])

	// [S-B3] Part 1: Mismatched context_epoch short-circuits BEFORE IssueHistoryDisclosureV1,
	// writing zero durable permit rows into bot_permission_disclosure_permit.
	hdrRef9501 := dmPage.Items[3].Header.HeaderReference
	hdrRef9505 := dmPage.Items[0].Header.HeaderReference

	hdBadEpochBytes, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("3", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("4", 32),
		"context_epoch":   "999",
		"headers": []any{
			map[string]any{"header_reference": hdrRef9501},
		},
	})))
	require.NoError(t, err)
	hdBadEpochRes := fixtureObject(t, hdBadEpochBytes)["results"].([]any)
	require.Len(t, hdBadEpochRes, 1)
	require.Equal(t, "unavailable", hdBadEpochRes[0].(map[string]any)["status"])
	require.Equal(t, "expired_reference", hdBadEpochRes[0].(map[string]any)["reason"])
	require.Nil(t, hdBadEpochRes[0].(map[string]any)["permit"])

	var permitCountAfterBadEpoch int
	err = f.s.Session.QueryRow("SELECT COUNT(*) FROM " + ServerDisclosurePermitTable).Scan(&permitCountAfterBadEpoch)
	require.NoError(t, err)
	require.Equal(t, 0, permitCountAfterBadEpoch, "mismatched context_epoch must not insert durable permit rows")

	// Matching context_epoch ("0") while scope base facts hold issues the permit and records 1 row.
	hdGoodEpochBytes, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("5", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("4", 32),
		"context_epoch":   "0",
		"headers": []any{
			map[string]any{"header_reference": hdrRef9501},
		},
	})))
	require.NoError(t, err)
	hdGoodEpochRes := fixtureObject(t, hdGoodEpochBytes)["results"].([]any)
	require.Equal(t, "resolved", hdGoodEpochRes[0].(map[string]any)["status"])
	require.NotEmpty(t, hdGoodEpochRes[0].(map[string]any)["permit"])

	var permitCountAfterGoodEpoch int
	err = f.s.Session.QueryRow("SELECT COUNT(*) FROM " + ServerDisclosurePermitTable).Scan(&permitCountAfterGoodEpoch)
	require.NoError(t, err)
	require.Equal(t, 1, permitCountAfterGoodEpoch)

	// [S-B3] Part 2: readHistoryDisclosure enforces evalScopeBaseFacts (botSpaceMember, spaceActive, botUserActive, botRobotActive)
	// even when bot_permission_scope.retired == 0 (both on direct SQLNativeFactAdapter.Read and Runtime.Facts).
	hdReq9505 := canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("6", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("7", 32),
		"context_epoch":   "0",
		"headers": []any{
			map[string]any{"header_reference": hdrRef9505},
		},
	})
	f.exec("UPDATE space_member SET status=0 WHERE space_id='space' AND uid='bot'")
	tx1, err := f.s.Session.Begin()
	require.NoError(t, err)
	_, err = adapter.Read(ctx, tx1, fixtureKey, hdReq9505)
	tx1.RollbackUnlessCommitted()
	require.ErrorIs(t, err, ErrUnavailable, "departed bot space_member must fail closed in SQLNativeFactAdapter.readHistoryDisclosure")
	_, err = rt.Facts(ctx, fixtureKey, bytes.NewReader(hdReq9505))
	require.ErrorIs(t, err, ErrForbidden, "departed bot space_member must fail closed in Runtime.Facts(history_disclosure)")

	f.exec("UPDATE space_member SET status=1 WHERE space_id='space' AND uid='bot'")
	f.exec("UPDATE space SET status=0 WHERE space_id='space'")
	tx2, err := f.s.Session.Begin()
	require.NoError(t, err)
	_, err = adapter.Read(ctx, tx2, fixtureKey, hdReq9505)
	tx2.RollbackUnlessCommitted()
	require.ErrorIs(t, err, ErrUnavailable, "deactivated space must fail closed in SQLNativeFactAdapter.readHistoryDisclosure")
	_, err = rt.Facts(ctx, fixtureKey, bytes.NewReader(hdReq9505))
	require.ErrorIs(t, err, ErrForbidden, "deactivated space must fail closed in Runtime.Facts(history_disclosure)")

	var permitCountFor9505 int
	err = f.s.Session.QueryRow("SELECT COUNT(*) FROM "+ServerDisclosurePermitTable+" WHERE header_reference=?", hdrRef9505).Scan(&permitCountFor9505)
	require.NoError(t, err)
	require.Equal(t, 0, permitCountFor9505)
}

func TestServerMessageFactsNativeCurrentACLGroupAndThreadAdmissionAndPreJoinHistory(t *testing.T) {
	ctx := t.Context()
	driver := newSyntheticExternalAuthorityDriver(fixturePin.Digest)
	authority, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)
	f := newServerFacts(t)
	f.s.Authority = authority
	f.exec(ServerDisclosurePermitDDL)
	f.p.durablePermits = true

	// Provision scope so Runtime.Facts(history_disclosure) validates context_epoch="0".
	_, err = f.s.Get(ctx, fixtureKey, "owner")
	require.NoError(t, err)

	adapter, err := NewSQLNativeFactAdapter(authority, f.p)
	require.NoError(t, err)
	adapter.testNoLocks = true
	c := &config.Context{}
	require.NoError(t, Install(c, f.s, fixturePin, adapter))
	rt := RuntimeFor(c)
	require.NotNil(t, rt)

	// 1. Receive-before-persistence timing (mirror_lag) boundary:
	// Before the message row is persisted by webhook notify, BindDeliveredMessage
	// fails closed with mirror_lag and never infers authority from a transport frame.
	preJoinPayload := map[string]any{"type": 1, "content": "PRE-JOIN-GROUP-SECRET-1"}
	preJoinDigest := sha256OfJSON(preJoinPayload)
	postCutoffPayload := map[string]any{"type": 1, "content": "POST-CUTOFF-GROUP-SECRET-2"}
	postCutoffDigest := sha256OfJSON(postCutoffPayload)
	threadPayload := map[string]any{"type": 1, "content": "CURRENT-THREAD-SECRET-1"}
	threadDigest := sha256OfJSON(threadPayload)

	callBind := func(reqID string, ctype int, ch, msgID, seq, from, digest string) map[string]any {
		out, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
			"schema_version":          json.Number("1"),
			"operation":               "bind_delivery",
			"request_id":              reqID,
			"channel_type":            json.Number(strconv.Itoa(ctype)),
			"channel_id":              ch,
			"message_id":              msgID,
			"message_seq":             seq,
			"from_uid":                from,
			"observed_payload_sha256": digest,
		})))
		require.NoError(t, err)
		for _, secret := range []string{"PRE-JOIN-GROUP-SECRET-1", "POST-CUTOFF-GROUP-SECRET-2", "CURRENT-THREAD-SECRET-1", "EDITED-VISIBLES-SECRET"} {
			require.NotContains(t, string(out), secret)
		}
		return fixtureObject(t, out)["binding"].(map[string]any)
	}

	unpersisted := callBind("req-pre-persist-1", 2, "group", "2123284828068417536", "1", "peer", preJoinDigest)
	require.Equal(t, "refused", unpersisted["status"])
	require.Equal(t, "mirror_lag", unpersisted["reason"])
	require.Equal(t, false, unpersisted["current"])

	// 2. Persist messages sent before/after Bot joined (Owner product semantics:
	// joining a group grants full history access under native current ACL without
	// any send-time or first-persist membership witness table).
	f.msgWithExpire("2123284828068417536", 1, "peer", "group", 2, 1700000001, 0, preJoinPayload)
	f.msgWithExpire("2123284828068417537", 2, "peer", "group", 2, 1700000002, 0, postCutoffPayload)
	f.msgWithExpire("2123284828068417538", 1, "peer", f.threadCh, 5, 1700000003, 0, threadPayload)

	boundPreJoin := callBind("req-bound-prejoin-1", 2, "group", "2123284828068417536", "1", "peer", preJoinDigest)
	require.Equal(t, "bound", boundPreJoin["status"])
	require.Equal(t, true, boundPreJoin["current"])
	require.Empty(t, boundPreJoin["unknown_predicates"].([]any))
	require.Equal(t, []any{"admit", "contributor", "reply"}, boundPreJoin["resolvable_purposes"].([]any))
	preJoinProven := boundPreJoin["proven_predicates"].(map[string]any)
	require.Equal(t, true, preJoinProven["caller_current_read"])
	require.Equal(t, true, preJoinProven["bot_current_read"])
	require.Equal(t, true, preJoinProven["caller_original_visible"])
	require.Equal(t, true, preJoinProven["bot_original_visible"])
	delivRef1 := boundPreJoin["delivery_reference"].(string)
	hdrRef1 := boundPreJoin["header_reference"].(string)

	boundPostCutoff := callBind("req-bound-postcutoff-2", 2, "group", "2123284828068417537", "2", "peer", postCutoffDigest)
	require.Equal(t, "bound", boundPostCutoff["status"])
	delivRef2 := boundPostCutoff["delivery_reference"].(string)
	hdrRef2 := boundPostCutoff["header_reference"].(string)

	boundThread := callBind("req-bound-thread-1", 5, f.threadCh, "2123284828068417538", "1", "peer", threadDigest)
	require.Equal(t, "bound", boundThread["status"])
	require.Empty(t, boundThread["unknown_predicates"].([]any))
	require.Equal(t, []any{"admit", "contributor", "reply"}, boundThread["resolvable_purposes"].([]any))
	delivRefThread := boundThread["delivery_reference"].(string)
	hdrRefThread := boundThread["header_reference"].(string)

	// 3. Resolve for admit, contributor, and reply succeeds for both group and thread messages.
	for _, purpose := range []string{"admit", "contributor", "reply"} {
		resOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
			"schema_version":  json.Number("1"),
			"profile_version": json.Number("1"),
			"request_id":      hex.EncodeToString([]byte("grp-res-" + purpose + "----------------")[:16]),
			"operation":       "resolve",
			"purpose":         purpose,
			"references": []any{
				map[string]any{"delivery_reference": delivRef1},
				map[string]any{"delivery_reference": delivRef2},
				map[string]any{"delivery_reference": delivRefThread},
			},
		})))
		require.NoError(t, err, purpose)
		results := fixtureObject(t, resOut)["results"].([]any)
		require.Len(t, results, 3)
		for idx, raw := range results {
			item := raw.(map[string]any)
			require.Equal(t, "resolved", item["status"], "%s idx %d", purpose, idx)
			preds := item["predicates"].(map[string]any)
			for k, v := range preds {
				require.Equal(t, true, v, "%s idx %d pred %s", purpose, idx, k)
			}
		}
	}

	// 4. Two-step history_headers + history_disclosure succeeds for pre-join group and thread messages.
	hhGroupOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":   json.Number("1"),
		"profile_version":  json.Number("1"),
		"request_id":       strings.Repeat("a", 32),
		"operation":        "history_headers",
		"source_reference": ServerSourceReference(2, "group"),
		"cursor":           nil,
		"page_size":        json.Number("10"),
	})))
	require.NoError(t, err)
	hhGroupItems := fixtureObject(t, hhGroupOut)["page"].(map[string]any)["items"].([]any)
	require.Len(t, hhGroupItems, 2)
	require.Equal(t, "2123284828068417537", hhGroupItems[0].(map[string]any)["message_id"])
	require.Equal(t, "2123284828068417536", hhGroupItems[1].(map[string]any)["message_id"])

	hdOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("b", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("1", 32),
		"context_epoch":   "0",
		"headers": []any{
			map[string]any{"header_reference": hdrRef1},
			map[string]any{"header_reference": hdrRefThread},
		},
	})))
	require.NoError(t, err)
	hdResults := fixtureObject(t, hdOut)["results"].([]any)
	require.Len(t, hdResults, 2)
	require.Equal(t, "resolved", hdResults[0].(map[string]any)["status"])
	permit1 := hdResults[0].(map[string]any)["permit"].(string)
	require.NotEmpty(t, permit1)
	require.Equal(t, "resolved", hdResults[1].(map[string]any)["status"])
	permitThread := hdResults[1].(map[string]any)["permit"].(string)
	require.NotEmpty(t, permitThread)
	require.NoError(t, f.p.ConsumeDisclosurePermitContext(ctx, fixtureKey, strings.Repeat("1", 32), "0", hdrRef1, preJoinDigest, permit1))
	require.ErrorIs(t, f.p.ConsumeDisclosurePermitContext(ctx, fixtureKey, strings.Repeat("1", 32), "0", hdrRef1, preJoinDigest, permit1), ErrReference)

	// 5. Join-time history cutoff (allow_view_history_msg=0 -> channel_offset.message_seq = 1 for bot):
	// Message seq=1 (at/before offset) is now refused by bind_delivery, resolve, history_headers, and history_disclosure,
	// while message seq=2 (after offset) remains accessible!
	f.exec("INSERT INTO channel_offset VALUES('bot','group',2,1)")

	cutBind1 := callBind("req-cutoff-bind-1", 2, "group", "2123284828068417536", "1", "peer", preJoinDigest)
	require.Equal(t, "refused", cutBind1["status"])
	require.Equal(t, "visibility_denied", cutBind1["reason"])

	cutBind2 := callBind("req-cutoff-bind-2", 2, "group", "2123284828068417537", "2", "peer", postCutoffDigest)
	require.Equal(t, "bound", cutBind2["status"])

	resCutOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("c", 32),
		"operation":       "resolve",
		"purpose":         "admit",
		"references": []any{
			map[string]any{"delivery_reference": delivRef1},
			map[string]any{"delivery_reference": delivRef2},
		},
	})))
	require.NoError(t, err)
	resCutItems := fixtureObject(t, resCutOut)["results"].([]any)
	predsCut1 := resCutItems[0].(map[string]any)["predicates"].(map[string]any)
	require.Equal(t, false, predsCut1["bot_current_read"])
	require.Equal(t, false, predsCut1["bot_original_visible"])
	predsCut2 := resCutItems[1].(map[string]any)["predicates"].(map[string]any)
	require.Equal(t, true, predsCut2["bot_current_read"])
	require.Equal(t, true, predsCut2["bot_original_visible"])

	hhCutPage, err := f.p.ListHistoryHeadersV1(ctx, fixtureKey, ServerSourceReference(2, "group"), nil, 10)
	require.NoError(t, err)
	require.Len(t, hhCutPage.Items, 2)
	require.Equal(t, "resolved", hhCutPage.Items[0].Status, "seq 2 > channel_offset 1 remains visible")
	require.Equal(t, "unavailable", hhCutPage.Items[1].Status, "seq 1 <= channel_offset 1 is hidden")
	require.Equal(t, "expired_reference", hhCutPage.Items[1].Reason)

	hdCutOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("d", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("2", 32),
		"context_epoch":   "0",
		"headers": []any{
			map[string]any{"header_reference": hdrRef1},
			map[string]any{"header_reference": hdrRef2},
		},
	})))
	require.NoError(t, err)
	hdCutRes := fixtureObject(t, hdCutOut)["results"].([]any)
	require.Equal(t, "unavailable", hdCutRes[0].(map[string]any)["status"])
	require.Equal(t, "disclosure_unavailable", hdCutRes[0].(map[string]any)["reason"])
	require.Equal(t, "resolved", hdCutRes[1].(map[string]any)["status"])
	require.NotEmpty(t, hdCutRes[1].(map[string]any)["permit"])

	// 6. Edited payload visibles exclusion and caller departure/removal also refuse disclosure and binding.
	editedVisibles := `{"content":"EDITED-VISIBLES-SECRET","type":1,"visibles":["peer"]}`
	editedVisSum := sha256.Sum256([]byte(editedVisibles))
	editedVisDigest := hex.EncodeToString(editedVisSum[:])
	f.exec("INSERT INTO message_extra VALUES('2123284828068417537',3,0,0,?,'v33')", editedVisibles)

	visBind := callBind("req-vis-bind-2", 2, "group", "2123284828068417537", "2", "peer", editedVisDigest)
	require.Equal(t, "refused", visBind["status"])
	require.Equal(t, "visibility_denied", visBind["reason"])

	hdrRef2Edited := encodeServerRef(serverRefHeader, serverRef{channelType: 2, channelID: "group", messageID: "2123284828068417537", version: "x3_v33"})
	visDisc, _, err := f.p.IssueHistoryDisclosureV1(ctx, fixtureKey, "ctx-vis", "0", []string{hdrRef2Edited})
	require.NoError(t, err)
	require.Equal(t, "unavailable", visDisc[0].Status)
	require.Equal(t, "disclosure_unavailable", visDisc[0].Reason)

	// Caller removal in parent group revokes thread binding and disclosure as well.
	f.exec("UPDATE group_member SET is_deleted=1 WHERE group_no=? AND uid='peer'", f.parent)
	thdRemovedCallerBind := callBind("req-thd-removed-caller", 5, f.threadCh, "2123284828068417538", "1", "peer", threadDigest)
	require.Equal(t, "refused", thdRemovedCallerBind["status"])
	require.Equal(t, "visibility_denied", thdRemovedCallerBind["reason"])

	thdRemovedCallerDisc, _, err := f.p.IssueHistoryDisclosureV1(ctx, fixtureKey, "ctx-thd-rem", "0", []string{hdrRefThread})
	require.NoError(t, err)
	require.Equal(t, "unavailable", thdRemovedCallerDisc[0].Status)
	require.Equal(t, "disclosure_unavailable", thdRemovedCallerDisc[0].Reason)
}

func TestServerMessageFactsLiveMySQLNativeCurrentACLGroupAndDMBinding(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OCTO_TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("OCTO_TEST_MYSQL_DSN not set; skipping live MySQL 8 integration check")
	}
	ctx := t.Context()
	conn, err := dbr.Open("mysql", dsn, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	for i := 0; i < 30; i++ {
		if err = conn.Ping(); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.NoError(t, err)
	sess := conn.NewSession(nil)

	for _, ddl := range []string{
		"DROP TABLE IF EXISTS bot_permission_authority_lineage, bot_permission_disclosure_permit, bot_permission_lineage, bot_permission_replay_journal, bot_permission_bundle_history, bot_permission_bundle_current, bot_permission_scope, channel_setting, channel_offset, message_user_extra, message_extra, message, thread, group_member, `group`, user_setting, friend, space_member, space, app_bot, robot, user",
		"CREATE TABLE user(id BIGINT PRIMARY KEY AUTO_INCREMENT, uid VARCHAR(128) NOT NULL UNIQUE, status INT NOT NULL, is_destroy INT NOT NULL DEFAULT 0, robot INT NOT NULL DEFAULT 0) ENGINE=InnoDB",
		"CREATE TABLE robot(id BIGINT PRIMARY KEY AUTO_INCREMENT, robot_id VARCHAR(128) NOT NULL UNIQUE, creator_uid VARCHAR(128) NOT NULL, status INT NOT NULL) ENGINE=InnoDB",
		"CREATE TABLE app_bot(id BIGINT PRIMARY KEY AUTO_INCREMENT, uid VARCHAR(128) NOT NULL UNIQUE, status INT NOT NULL DEFAULT 0) ENGINE=InnoDB",
		"CREATE TABLE space(id BIGINT PRIMARY KEY AUTO_INCREMENT, space_id VARCHAR(128) NOT NULL UNIQUE, status INT NOT NULL) ENGINE=InnoDB",
		"CREATE TABLE space_member(space_id VARCHAR(128) NOT NULL, uid VARCHAR(128) NOT NULL, status INT NOT NULL, PRIMARY KEY(space_id, uid)) ENGINE=InnoDB",
		"CREATE TABLE friend(uid VARCHAR(128) NOT NULL, to_uid VARCHAR(128) NOT NULL, is_deleted INT NOT NULL DEFAULT 0, is_alone INT NOT NULL DEFAULT 0, PRIMARY KEY(uid, to_uid)) ENGINE=InnoDB",
		"CREATE TABLE user_setting(uid VARCHAR(128) NOT NULL, to_uid VARCHAR(128) NOT NULL, blacklist INT NOT NULL DEFAULT 0, PRIMARY KEY(uid, to_uid)) ENGINE=InnoDB",
		"CREATE TABLE `group`(group_no VARCHAR(128) NOT NULL PRIMARY KEY, space_id VARCHAR(128) NOT NULL, status INT NOT NULL) ENGINE=InnoDB",
		"CREATE TABLE group_member(group_no VARCHAR(128) NOT NULL, uid VARCHAR(128) NOT NULL, status INT NOT NULL DEFAULT 1, is_deleted INT NOT NULL DEFAULT 0, is_external INT NOT NULL DEFAULT 0, PRIMARY KEY(group_no, uid)) ENGINE=InnoDB",
		"CREATE TABLE thread(group_no VARCHAR(128) NOT NULL, short_id VARCHAR(64) NOT NULL, status INT NOT NULL, PRIMARY KEY(group_no, short_id)) ENGINE=InnoDB",
		"CREATE TABLE message(message_id VARCHAR(64) NOT NULL PRIMARY KEY, message_seq BIGINT NOT NULL, from_uid VARCHAR(128) NOT NULL, channel_id VARCHAR(191) NOT NULL, channel_type INT NOT NULL, `timestamp` BIGINT NOT NULL, payload LONGBLOB NOT NULL, is_deleted INT NOT NULL DEFAULT 0, expire BIGINT NOT NULL DEFAULT 0) ENGINE=InnoDB",
		"CREATE TABLE message_extra(message_id VARCHAR(64) NOT NULL PRIMARY KEY, version INT NOT NULL DEFAULT 0, `revoke` INT NOT NULL DEFAULT 0, is_deleted INT NOT NULL DEFAULT 0, content_edit LONGTEXT NULL, content_edit_hash VARCHAR(128) NOT NULL DEFAULT '') ENGINE=InnoDB",
		"CREATE TABLE message_user_extra(uid VARCHAR(128) NOT NULL, message_id VARCHAR(64) NOT NULL, message_is_deleted INT NOT NULL DEFAULT 0, PRIMARY KEY(uid, message_id)) ENGINE=InnoDB",
		"CREATE TABLE channel_offset(uid VARCHAR(128) NOT NULL, channel_id VARCHAR(191) NOT NULL, channel_type INT NOT NULL, message_seq BIGINT NOT NULL, PRIMARY KEY(uid, channel_id, channel_type)) ENGINE=InnoDB",
		"CREATE TABLE channel_setting(channel_id VARCHAR(191) NOT NULL, channel_type INT NOT NULL, offset_message_seq BIGINT NOT NULL, PRIMARY KEY(channel_id, channel_type)) ENGINE=InnoDB",
		"CREATE TABLE bot_permission_scope(bot_uid VARBINARY(128) NOT NULL, space_id VARBINARY(128) NOT NULL, scope_incarnation VARBINARY(128) NOT NULL UNIQUE, revision VARCHAR(64) NOT NULL, context_epoch VARCHAR(64) NOT NULL, schema_version INT NOT NULL, catalog_version VARCHAR(64) NOT NULL, catalog_digest VARBINARY(128) NOT NULL, bundle_json LONGTEXT NOT NULL, bundle_digest VARBINARY(128) NOT NULL, native_anchor_json LONGTEXT NOT NULL, native_anchor_digest VARBINARY(128) NOT NULL, retired INT NOT NULL DEFAULT 0, updated_by VARCHAR(128) NULL, updated_at DATETIME(6) NOT NULL, PRIMARY KEY(bot_uid, space_id)) ENGINE=InnoDB",
		NativeAuthorityLineageDDL,
		ServerDisclosurePermitDDL,
	} {
		_, err := sess.Exec(ddl)
		require.NoError(t, err, ddl)
	}

	parent := strings.Repeat("1", 32)
	threadCh := parent + "____123456789012345"
	pair, err := PairReference("bot", "peer")
	require.NoError(t, err)
	dmChan := pair["id"].(string)

	for _, seedQ := range []string{
		"INSERT INTO user(uid,status,is_destroy,robot) VALUES('bot',1,0,1),('owner',1,0,0),('peer',1,0,0),('departed',1,0,0)",
		"INSERT INTO robot(robot_id,creator_uid,status) VALUES('bot','owner',1)",
		"INSERT INTO space(space_id,status) VALUES('space',1)",
		"INSERT INTO space_member(space_id,uid,status) VALUES('space','bot',1),('space','owner',1),('space','peer',1),('space','departed',0)",
		"INSERT INTO friend(uid,to_uid,is_deleted,is_alone) VALUES('peer','bot',0,0),('bot','peer',0,0)",
		"INSERT INTO `group`(group_no,space_id,status) VALUES('group','space',1),('" + parent + "','space',1)",
		"INSERT INTO group_member(group_no,uid,status,is_deleted,is_external) VALUES('group','bot',1,0,0),('group','peer',1,0,0),('group','departed',1,1,0),('" + parent + "','bot',1,0,0),('" + parent + "','peer',1,0,0)",
		"INSERT INTO thread(group_no,short_id,status) VALUES('" + parent + "','123456789012345',1)",
	} {
		_, err := sess.Exec(seedQ)
		require.NoError(t, err, seedQ)
	}

	driver, err := NewNativeSingleWriterLineageDriver(NativeSingleWriterLineageConfig{
		Session:       sess,
		Origin:        fixtureKey.Origin,
		AuthorityID:   "mysql8-single-writer-test",
		Incarnation:   strings.Repeat("a", 32),
		CatalogDigest: fixturePin.Digest,
		StatePath:     filepath.Join(t.TempDir(), "mysql8-authority-state.json"),
		Key:           []byte(strings.Repeat("m", 32)),
		Provision:     true,
		testNoLocks:   false,
	})
	require.NoError(t, err)
	authority, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)
	s := Store{
		Session:   sess,
		Origin:    fixtureKey.Origin,
		Authority: authority,
		Native:    SQLNative{},
		Releases:  fixtureReleases{},
	}
	txAssoc, err := sess.Begin()
	require.NoError(t, err)
	defer txAssoc.RollbackUnlessCommitted()
	anchor, err := s.Native.Scope(ctx, txAssoc, fixtureKey, "owner", strings.Repeat("a", 32))
	require.NoError(t, err)
	require.NoError(t, s.ProvisionSuffix(ctx, txAssoc, fixtureKey, anchor, fixturePin))
	require.NoError(t, txAssoc.Commit())
	_, err = s.Get(ctx, fixtureKey, "owner")
	require.NoError(t, err)

	p, err := NewServerMessageFactProvider(ServerMessageFactConfig{
		Session:             sess,
		Hooks:               testServerHooks(),
		StoreIncarnation:    strings.Repeat("5", 32),
		PermitKey:           []byte(strings.Repeat("k", 32)),
		DurablePermitLedger: true,
	})
	require.NoError(t, err)
	adapter, err := NewSQLNativeFactAdapter(authority, p)
	require.NoError(t, err)
	// Keep adapter.testNoLocks == false so real MySQL 8 FOR SHARE NOWAIT / FOR SHARE execute!
	c := &config.Context{}
	require.NoError(t, Install(c, s, fixturePin, adapter))
	rt := RuntimeFor(c)
	require.NotNil(t, rt)

	dmPayload := map[string]any{"type": 1, "space_id": "space", "content": "MYSQL-LIVE-DM-SECRET"}
	dmBytes, _ := json.Marshal(dmPayload)
	dmDigest := sha256OfJSON(dmPayload)
	_, err = sess.Exec("INSERT INTO message VALUES('2123243234824982528',4,'peer',?,1,1700000001,?,0,0)", dmChan, dmBytes)
	require.NoError(t, err)

	grpPayload := map[string]any{"type": 1, "content": "MYSQL-LIVE-GROUP-PREJOIN-SECRET"}
	grpBytes, _ := json.Marshal(grpPayload)
	grpDigest := sha256OfJSON(grpPayload)
	_, err = sess.Exec("INSERT INTO message VALUES('2123284828068417536',1,'peer','group',2,1700000002,?,0,0)", grpBytes)
	require.NoError(t, err)

	thdPayload := map[string]any{"type": 1, "content": "MYSQL-LIVE-THREAD-SECRET"}
	thdBytes, _ := json.Marshal(thdPayload)
	thdDigest := sha256OfJSON(thdPayload)
	_, err = sess.Exec("INSERT INTO message VALUES('2123284828068417538',1,'peer',?,5,1700000003,?,0,0)", threadCh, thdBytes)
	require.NoError(t, err)

	// 1. Bare-peer DM bind_delivery on real MySQL 8 with FOR SHARE NOWAIT and quoted `revoke`.
	dmBindOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "mysql-dm-bind-1",
		"channel_type":            json.Number("1"),
		"channel_id":              "peer",
		"message_id":              "2123243234824982528",
		"message_seq":             "4",
		"from_uid":                "peer",
		"observed_payload_sha256": dmDigest,
	})))
	require.NoError(t, err)
	dmBinding := fixtureObject(t, dmBindOut)["binding"].(map[string]any)
	require.Equal(t, "bound", dmBinding["status"])
	require.Equal(t, []any{"admit", "contributor", "reply"}, dmBinding["resolvable_purposes"].([]any))

	// 2. Group and thread bind_delivery, resolve(admit|contributor|reply), and history_disclosure on real MySQL 8.
	grpBindOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "mysql-grp-bind-1",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"message_id":              "2123284828068417536",
		"message_seq":             "1",
		"from_uid":                "peer",
		"observed_payload_sha256": grpDigest,
	})))
	require.NoError(t, err)
	grpBinding := fixtureObject(t, grpBindOut)["binding"].(map[string]any)
	require.Equal(t, "bound", grpBinding["status"])
	require.Empty(t, grpBinding["unknown_predicates"].([]any))
	require.Equal(t, []any{"admit", "contributor", "reply"}, grpBinding["resolvable_purposes"].([]any))
	grpDelivRef := grpBinding["delivery_reference"].(string)
	grpHdrRef := grpBinding["header_reference"].(string)

	thdBindOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "mysql-thd-bind-1",
		"channel_type":            json.Number("5"),
		"channel_id":              threadCh,
		"message_id":              "2123284828068417538",
		"message_seq":             "1",
		"from_uid":                "peer",
		"observed_payload_sha256": thdDigest,
	})))
	require.NoError(t, err)
	thdBinding := fixtureObject(t, thdBindOut)["binding"].(map[string]any)
	require.Equal(t, "bound", thdBinding["status"])
	require.Empty(t, thdBinding["unknown_predicates"].([]any))
	require.Equal(t, []any{"admit", "contributor", "reply"}, thdBinding["resolvable_purposes"].([]any))
	thdDelivRef := thdBinding["delivery_reference"].(string)
	thdHdrRef := thdBinding["header_reference"].(string)

	resOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("9", 32),
		"operation":       "resolve",
		"purpose":         "admit",
		"references": []any{
			map[string]any{"delivery_reference": grpDelivRef},
			map[string]any{"delivery_reference": thdDelivRef},
		},
	})))
	require.NoError(t, err)
	resItems := fixtureObject(t, resOut)["results"].([]any)
	require.Equal(t, "resolved", resItems[0].(map[string]any)["status"])
	require.Equal(t, "resolved", resItems[1].(map[string]any)["status"])

	hdOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("8", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("7", 32),
		"context_epoch":   "0",
		"headers": []any{
			map[string]any{"header_reference": grpHdrRef},
			map[string]any{"header_reference": thdHdrRef},
		},
	})))
	require.NoError(t, err)
	hdItems := fixtureObject(t, hdOut)["results"].([]any)
	require.Equal(t, "resolved", hdItems[0].(map[string]any)["status"])
	require.NotEmpty(t, hdItems[0].(map[string]any)["permit"])
	require.Equal(t, "resolved", hdItems[1].(map[string]any)["status"])
	require.NotEmpty(t, hdItems[1].(map[string]any)["permit"])

	// 3. Negative path on real MySQL 8: channel_offset join cutoff and message_extra.`revoke`=1 refuse.
	_, err = sess.Exec("INSERT INTO channel_offset VALUES('bot','group',2,1)")
	require.NoError(t, err)
	cutOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "mysql-grp-cutoff-1",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"message_id":              "2123284828068417536",
		"message_seq":             "1",
		"from_uid":                "peer",
		"observed_payload_sha256": grpDigest,
	})))
	require.NoError(t, err)
	require.Equal(t, "refused", fixtureObject(t, cutOut)["binding"].(map[string]any)["status"])
	require.Equal(t, "visibility_denied", fixtureObject(t, cutOut)["binding"].(map[string]any)["reason"])

	_, err = sess.Exec("INSERT INTO message_extra(message_id,version,`revoke`,is_deleted,content_edit,content_edit_hash) VALUES('2123284828068417536',1,1,0,NULL,'')")
	require.NoError(t, err)
	revOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "mysql-grp-revoke-1",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"message_id":              "2123284828068417536",
		"message_seq":             "1",
		"from_uid":                "peer",
		"observed_payload_sha256": grpDigest,
	})))
	require.NoError(t, err)
	require.Equal(t, "refused", fixtureObject(t, revOut)["binding"].(map[string]any)["status"])
	require.Equal(t, "expired_reference", fixtureObject(t, revOut)["binding"].(map[string]any)["reason"])

	// 4. Asynchronous ingress separation on real MySQL 8 with NO trigger message row in `message`:
	unpersistedDigest := sha256OfJSON(map[string]any{"type": 1, "content": "MYSQL-UNPERSISTED-LIVE-TRIGGER"})
	// Verify stored-row bind_delivery refuses with mirror_lag when row is not in MySQL:
	lagOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_delivery",
		"request_id":              "mysql-unpersisted-lag-1",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"message_id":              "2123339999999990001",
		"message_seq":             "99",
		"from_uid":                "peer",
		"observed_payload_sha256": unpersistedDigest,
	})))
	require.NoError(t, err)
	require.Equal(t, "refused", fixtureObject(t, lagOut)["binding"].(map[string]any)["status"])
	require.Equal(t, "mirror_lag", fixtureObject(t, lagOut)["binding"].(map[string]any)["reason"])

	// bind_live_ingress succeeds on real MySQL 8 without the trigger row (seq 99 > channel_offset 1):
	liveGrpOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_live_ingress",
		"request_id":              "mysql-live-grp-1",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"message_id":              "2123339999999990001",
		"message_seq":             "99",
		"from_uid":                "peer",
		"observed_payload_sha256": unpersistedDigest,
	})))
	require.NoError(t, err)
	liveGrpBinding := fixtureObject(t, liveGrpOut)["binding"].(map[string]any)
	require.Equal(t, "bound", liveGrpBinding["status"])
	require.Equal(t, LiveIngressProvenanceV1, liveGrpBinding["provenance"])
	require.Equal(t, false, liveGrpBinding["trigger_row_persisted"])
	require.Equal(t, false, liveGrpBinding["content_attested_by_server"])
	require.Equal(t, LiveUnpersistedMessageVersionV1, liveGrpBinding["native_message_version"])
	require.Equal(t, []any{"admit", "reply"}, liveGrpBinding["resolvable_purposes"].([]any))
	liveGrpDelivRef := liveGrpBinding["delivery_reference"].(string)
	require.True(t, strings.HasPrefix(liveGrpDelivRef, "l1-"))

	// resolve(admit) and resolve(reply) with l1-... succeed on real MySQL 8 without the trigger row:
	for idx, purpose := range []string{"admit", "reply"} {
		resLiveOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
			"schema_version":  json.Number("1"),
			"profile_version": json.Number("1"),
			"request_id":      strings.Repeat("a", 31) + strconv.Itoa(idx),
			"operation":       "resolve",
			"purpose":         purpose,
			"references": []any{
				map[string]any{"delivery_reference": liveGrpDelivRef},
			},
		})))
		require.NoError(t, err)
		resLiveItem := fixtureObject(t, resLiveOut)["results"].([]any)[0].(map[string]any)
		require.Equal(t, "resolved", resLiveItem["status"])
		for k, v := range resLiveItem["predicates"].(map[string]any) {
			require.Equal(t, true, v, "mysql live resolve %s pred %s", purpose, k)
		}
	}

	// evaluate_current_access succeeds on real MySQL 8 without the trigger row:
	evalLiveOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"profile_version":         json.Number("1"),
		"request_id":              "mysql-live-eval-admit",
		"operation":               "evaluate_current_access",
		"purpose":                 "admit",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"caller_uid":              "peer",
		"message_id":              "2123339999999990001",
		"message_seq":             "99",
		"observed_payload_sha256": unpersistedDigest,
	})))
	require.NoError(t, err)
	evalAccess := fixtureObject(t, evalLiveOut)["access"].(map[string]any)
	require.Equal(t, "evaluated", evalAccess["status"])
	require.Equal(t, true, evalAccess["eligible"])
	require.Equal(t, "group_admit_v1", evalAccess["profile"])
	require.Equal(t, false, evalAccess["trigger_row_persisted"])
	require.Equal(t, false, evalAccess["content_attested_by_server"])

	// 5. Concurrent single-writer lineage (NativeSingleWriterLineageDriver with real MySQL 8 InnoDB locks):
	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	for worker := 0; worker < 4; worker++ {
		w := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iter := 0; iter < 3; iter++ {
				bOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
					"schema_version":          json.Number("1"),
					"operation":               "bind_live_ingress",
					"request_id":              "mysql-conc-bind-" + strconv.Itoa(w) + "-" + strconv.Itoa(iter),
					"channel_type":            json.Number("2"),
					"channel_id":              "group",
					"message_id":              strconv.Itoa(9800000 + w*100 + iter),
					"message_seq":             strconv.Itoa(200 + w*10 + iter),
					"from_uid":                "peer",
					"observed_payload_sha256": unpersistedDigest,
				})))
				if err != nil {
					errCh <- err
					return
				}
				dRef := fixtureObject(t, bOut)["binding"].(map[string]any)["delivery_reference"].(string)
				_, err = rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
					"schema_version":  json.Number("1"),
					"profile_version": json.Number("1"),
					"request_id":      strings.Repeat("e", 30) + strconv.Itoa(w) + strconv.Itoa(iter),
					"operation":       "resolve",
					"purpose":         "admit",
					"references": []any{
						map[string]any{"delivery_reference": dRef},
					},
				})))
				if err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	// 6. Real MySQL 8 InnoDB concurrent webhook writer (`INSERT INTO message ... ON DUPLICATE KEY UPDATE`)
	// overlapping with bind_live_ingress and resolve(admit|reply):
	// Under the old FOR SHARE NOWAIT, touching the locked row/gap aborted immediately with Error 3572 (ER_LOCK_NOWAIT -> ErrUnavailable -> HTTP 400).
	// Under bounded FOR SHARE, concurrent readers wait cleanly for the millisecond writer to commit and succeed with HTTP 200.
	delayedMsgID := "2123350999999990001"
	delayedSeq := "305"
	delayedPayload := map[string]any{"type": 1, "content": "MYSQL-DELAYED-WEBHOOK-TRIGGER"}
	delayedBytes, _ := json.Marshal(delayedPayload)
	delayedDigest := sha256OfJSON(delayedPayload)

	// (a) Before webhook persistence (absent trigger): bind_live_ingress and resolve(admit) succeed with trigger_row_persisted=false.
	preBindOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_live_ingress",
		"request_id":              "mysql-delayed-pre-bind",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"message_id":              delayedMsgID,
		"message_seq":             delayedSeq,
		"from_uid":                "peer",
		"observed_payload_sha256": delayedDigest,
	})))
	require.NoError(t, err)
	preBinding := fixtureObject(t, preBindOut)["binding"].(map[string]any)
	require.Equal(t, "bound", preBinding["status"])
	require.Equal(t, false, preBinding["trigger_row_persisted"])
	require.Equal(t, false, preBinding["content_attested_by_server"])
	delayedLiveRef := preBinding["delivery_reference"].(string)
	preHeaderJSON := string(canonical(preBinding["header"]))

	// (b) Hold an uncommitted InnoDB transaction that inserts/locks delayedMsgID for 80ms while bind_live_ingress,
	// resolve(admit), resolve(reply), and Runtime.Get execute concurrently.
	writerTx, err := sess.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	require.NoError(t, err)
	_, err = writerTx.Exec(
		"INSERT INTO message VALUES(?,305,'peer','group',2,1700000305,?,0,0) ON DUPLICATE KEY UPDATE payload=payload",
		delayedMsgID, delayedBytes,
	)
	require.NoError(t, err)

	writerDone := make(chan error, 1)
	go func() {
		time.Sleep(80 * time.Millisecond)
		writerDone <- writerTx.Commit()
	}()

	var lockWg sync.WaitGroup
	lockErrCh := make(chan error, 8)
	var postCommitResolveHeader string
	lockWg.Add(3)
	go func() {
		defer lockWg.Done()
		_, bErr := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
			"schema_version":          json.Number("1"),
			"operation":               "bind_live_ingress",
			"request_id":              "mysql-delayed-during-lock-bind",
			"channel_type":            json.Number("2"),
			"channel_id":              "group",
			"message_id":              delayedMsgID,
			"message_seq":             delayedSeq,
			"from_uid":                "peer",
			"observed_payload_sha256": delayedDigest,
		})))
		if bErr != nil {
			lockErrCh <- bErr
		}
	}()
	go func() {
		defer lockWg.Done()
		rOut, rErr := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
			"schema_version":  json.Number("1"),
			"profile_version": json.Number("1"),
			"request_id":      strings.Repeat("d", 32),
			"operation":       "resolve",
			"purpose":         "reply",
			"references": []any{
				map[string]any{"delivery_reference": delayedLiveRef},
			},
		})))
		if rErr != nil {
			lockErrCh <- rErr
			return
		}
		item := fixtureObject(t, rOut)["results"].([]any)[0].(map[string]any)
		if item["status"] != "resolved" {
			lockErrCh <- errors.New("expected resolved status during concurrent writer commit")
			return
		}
		postCommitResolveHeader = string(canonical(item["header"]))
	}()
	go func() {
		defer lockWg.Done()
		if _, gErr := s.Get(ctx, fixtureKey, ""); gErr != nil {
			lockErrCh <- gErr
		}
	}()
	lockWg.Wait()
	require.NoError(t, <-writerDone)
	close(lockErrCh)
	for lErr := range lockErrCh {
		require.NoError(t, lErr)
	}
	require.Equal(t, preHeaderJSON, postCommitResolveHeader, "HeaderV1 must remain byte-identical after delayed trigger row persistence")

	// (c) Positive after delayed trigger persistence: bind_live_ingress now reports trigger_row_persisted=true, content_attested_by_server=true.
	postBindOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_live_ingress",
		"request_id":              "mysql-delayed-post-bind",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"message_id":              delayedMsgID,
		"message_seq":             delayedSeq,
		"from_uid":                "peer",
		"observed_payload_sha256": delayedDigest,
	})))
	require.NoError(t, err)
	postBinding := fixtureObject(t, postBindOut)["binding"].(map[string]any)
	require.Equal(t, "bound", postBinding["status"])
	require.Equal(t, true, postBinding["trigger_row_persisted"])
	require.Equal(t, true, postBinding["content_attested_by_server"])

	// (d) Negative after delayed trigger persistence: if the persisted trigger row is revoked or deleted mid-turn,
	// subsequent resolve(admit) and resolve(reply) on the live l1-... reference fail closed immediately.
	_, err = sess.Exec("INSERT INTO message_extra(message_id,version,`revoke`,is_deleted,content_edit,content_edit_hash) VALUES(?,1,1,0,NULL,'')", delayedMsgID)
	require.NoError(t, err)
	for idx, purpose := range []string{"admit", "reply"} {
		revLiveOut, rErr := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
			"schema_version":  json.Number("1"),
			"profile_version": json.Number("1"),
			"request_id":      strings.Repeat("c", 31) + strconv.Itoa(idx),
			"operation":       "resolve",
			"purpose":         purpose,
			"references": []any{
				map[string]any{"delivery_reference": delayedLiveRef},
			},
		})))
		require.NoError(t, rErr)
		revItem := fixtureObject(t, revLiveOut)["results"].([]any)[0].(map[string]any)
		require.Equal(t, "unavailable", revItem["status"])
		require.Equal(t, "expired_reference", revItem["reason"])
	}

	// (e) Verify SQL authority lineage committed_position == acknowledged_position (no double-Begin position drift).
	var committedPos, ackedPos, checkpointPos int64
	err = sess.QueryRow(
		"SELECT committed_position, acknowledged_position, recoverable_scope_checkpoint FROM " + NativeAuthorityLineageTable + " WHERE singleton=1",
	).Scan(&committedPos, &ackedPos, &checkpointPos)
	require.NoError(t, err)
	require.Equal(t, committedPos, ackedPos, "committed_position and acknowledged_position must match exactly")
	require.Equal(t, committedPos, checkpointPos, "recoverable_scope_checkpoint must match committed_position")
}

func TestServerMessageFactsAsyncIngressSeparationWithoutTriggerRow(t *testing.T) {
	ctx := t.Context()
	driver := newSyntheticExternalAuthorityDriver(fixturePin.Digest)
	authority, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)
	f := newServerFacts(t)
	f.s.Authority = authority
	f.exec(ServerDisclosurePermitDDL)
	f.p.durablePermits = true

	_, err = f.s.Get(ctx, fixtureKey, "owner")
	require.NoError(t, err)

	adapter, err := NewSQLNativeFactAdapter(authority, f.p)
	require.NoError(t, err)
	adapter.testNoLocks = true
	c := &config.Context{}
	require.NoError(t, Install(c, f.s, fixturePin, adapter))
	rt := RuntimeFor(c)
	require.NotNil(t, rt)

	// Confirm the `message` table has zero rows for our live ingress messages.
	dmPayload := map[string]any{"type": 1, "content": "LIVE-UNPERSISTED-DM"}
	dmDigest := sha256OfJSON(dmPayload)
	grpPayload := map[string]any{"type": 1, "content": "LIVE-UNPERSISTED-GROUP"}
	grpDigest := sha256OfJSON(grpPayload)
	thdPayload := map[string]any{"type": 1, "content": "LIVE-UNPERSISTED-THREAD"}
	thdDigest := sha256OfJSON(thdPayload)

	callBindOp := func(op, reqID string, chType uint8, chID, msgID, seq, fromUID, digest string) map[string]any {
		out, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
			"schema_version":          json.Number("1"),
			"operation":               op,
			"request_id":              reqID,
			"channel_type":            json.Number(strconv.FormatUint(uint64(chType), 10)),
			"channel_id":              chID,
			"message_id":              msgID,
			"message_seq":             seq,
			"from_uid":                fromUID,
			"observed_payload_sha256": digest,
		})))
		require.NoError(t, err)
		return fixtureObject(t, out)["binding"].(map[string]any)
	}

	callEvalAccess := func(reqID, purpose string, chType uint8, chID, callerUID, msgID, seq, digest string) map[string]any {
		req := map[string]any{
			"schema_version":  json.Number("1"),
			"profile_version": json.Number("1"),
			"request_id":      reqID,
			"operation":       "evaluate_current_access",
			"purpose":         purpose,
			"channel_type":    json.Number(strconv.FormatUint(uint64(chType), 10)),
			"channel_id":      chID,
			"caller_uid":      callerUID,
		}
		if msgID != "" {
			req["message_id"] = msgID
		}
		if seq != "" {
			req["message_seq"] = seq
		}
		if digest != "" {
			req["observed_payload_sha256"] = digest
		}
		out, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(req)))
		require.NoError(t, err)
		return fixtureObject(t, out)["access"].(map[string]any)
	}

	// 1. Stored-row bind_delivery still fails closed with mirror_lag when the row is not in MySQL.
	for _, tc := range []struct {
		name   string
		chType uint8
		chID   string
		msgID  string
		seq    string
		digest string
	}{
		{"dm_bare_peer", 1, "peer", "9100001", "10", dmDigest},
		{"group", 2, "group", "9100002", "11", grpDigest},
		{"thread", 5, f.threadCh, "9100003", "12", thdDigest},
	} {
		b := callBindOp("bind_delivery", "req-stored-lag-"+tc.name, tc.chType, tc.chID, tc.msgID, tc.seq, "peer", tc.digest)
		require.Equal(t, "refused", b["status"], tc.name)
		require.Equal(t, "mirror_lag", b["reason"], tc.name)
	}

	// 2. bind_live_ingress succeeds across DM (bare peer and canonical pair), Group, and Thread with zero rows in `message`.
	dmBind := callBindOp("bind_live_ingress", "req-live-dm-peer", 1, "peer", "9100001", "10", "peer", dmDigest)
	require.Equal(t, "bound", dmBind["status"])
	require.Equal(t, LiveIngressProvenanceV1, dmBind["provenance"])
	require.Equal(t, false, dmBind["trigger_row_persisted"])
	require.Equal(t, false, dmBind["content_attested_by_server"])
	require.Equal(t, LiveUnpersistedMessageVersionV1, dmBind["native_message_version"])
	require.Equal(t, []any{"admit", "reply"}, dmBind["resolvable_purposes"].([]any))
	dmLiveDelivRef := dmBind["delivery_reference"].(string)
	dmLiveHdrRef := dmBind["header_reference"].(string)
	require.True(t, strings.HasPrefix(dmLiveDelivRef, "l1-"))
	require.True(t, strings.HasPrefix(dmLiveHdrRef, "l2-"))

	dmPairBind := callBindOp("bind_live_ingress", "req-live-dm-pair", 1, f.dmChan, "9100001", "10", "peer", dmDigest)
	require.Equal(t, "bound", dmPairBind["status"])
	require.Equal(t, dmLiveDelivRef, dmPairBind["delivery_reference"], "bare peer and canonical DM pair mint identical l1 reference")

	grpBind := callBindOp("bind_live_ingress", "req-live-grp", 2, "group", "9100002", "11", "peer", grpDigest)
	require.Equal(t, "bound", grpBind["status"])
	require.Equal(t, false, grpBind["trigger_row_persisted"])
	require.Equal(t, false, grpBind["content_attested_by_server"])
	grpLiveDelivRef := grpBind["delivery_reference"].(string)
	grpLiveHdrRef := grpBind["header_reference"].(string)

	thdBind := callBindOp("bind_live_ingress", "req-live-thd", 5, f.threadCh, "9100003", "12", "peer", thdDigest)
	require.Equal(t, "bound", thdBind["status"])
	require.Equal(t, false, thdBind["trigger_row_persisted"])
	require.Equal(t, false, thdBind["content_attested_by_server"])
	thdLiveDelivRef := thdBind["delivery_reference"].(string)
	thdLiveHdrRef := thdBind["header_reference"].(string)

	// 3. resolve(admit) and resolve(reply) with l1-... succeed with all predicates true and byte-identical headers.
	admitHeaders := map[string]string{}
	for pIdx, purpose := range []string{"admit", "reply"} {
		resOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
			"schema_version":  json.Number("1"),
			"profile_version": json.Number("1"),
			"request_id":      strings.Repeat("b", 31) + strconv.Itoa(pIdx),
			"operation":       "resolve",
			"purpose":         purpose,
			"references": []any{
				map[string]any{"delivery_reference": dmLiveDelivRef},
				map[string]any{"delivery_reference": grpLiveDelivRef},
				map[string]any{"delivery_reference": thdLiveDelivRef},
			},
		})))
		require.NoError(t, err)
		results := fixtureObject(t, resOut)["results"].([]any)
		require.Len(t, results, 3)
		for idx, raw := range results {
			item := raw.(map[string]any)
			require.Equal(t, "resolved", item["status"], "%s idx %d", purpose, idx)
			hdrJSON := string(canonical(item["header"]))
			if purpose == "admit" {
				admitHeaders[item["reference"].(string)] = hdrJSON
			} else {
				require.Equal(t, admitHeaders[item["reference"].(string)], hdrJSON, "admit and reply headers must be byte-identical")
			}
			for k, v := range item["predicates"].(map[string]any) {
				require.Equal(t, true, v, "%s idx %d pred %s", purpose, idx, k)
			}
		}
	}

	// 4. resolve(contributor) with unpersisted l1-... is refused with mirror_lag (no fake content attestation).
	contribOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("c", 32),
		"operation":       "resolve",
		"purpose":         "contributor",
		"references": []any{
			map[string]any{"delivery_reference": dmLiveDelivRef},
			map[string]any{"delivery_reference": grpLiveDelivRef},
			map[string]any{"delivery_reference": thdLiveDelivRef},
		},
	})))
	require.NoError(t, err)
	for _, raw := range fixtureObject(t, contribOut)["results"].([]any) {
		item := raw.(map[string]any)
		require.Equal(t, "unavailable", item["status"])
		require.Equal(t, "mirror_lag", item["reason"])
	}

	// 5. history_disclosure rejects l2-... live header references with predicate_unsupported.
	hdLiveOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("d", 32),
		"operation":       "history_disclosure",
		"context_id":      strings.Repeat("1", 32),
		"context_epoch":   "0",
		"headers": []any{
			map[string]any{"header_reference": dmLiveHdrRef},
			map[string]any{"header_reference": grpLiveHdrRef},
			map[string]any{"header_reference": thdLiveHdrRef},
		},
	})))
	require.NoError(t, err)
	for _, raw := range fixtureObject(t, hdLiveOut)["results"].([]any) {
		item := raw.(map[string]any)
		require.Equal(t, "unavailable", item["status"])
		require.Equal(t, "predicate_unsupported", item["reason"])
	}

	// 6. evaluate_current_access succeeds for DM, Group, and Thread (both admit and reply, with or without message fields).
	for _, purpose := range []string{"admit", "reply"} {
		dmAcc := callEvalAccess("req-eval-dm-"+purpose, purpose, 1, "peer", "peer", "9100001", "10", dmDigest)
		require.Equal(t, "evaluated", dmAcc["status"])
		require.Equal(t, true, dmAcc["eligible"])
		require.Equal(t, "dm_"+purpose+"_v1", dmAcc["profile"])
		require.Equal(t, false, dmAcc["trigger_row_persisted"])
		require.Equal(t, false, dmAcc["content_attested_by_server"])

		grpAcc := callEvalAccess("req-eval-grp-"+purpose, purpose, 2, "group", "peer", "", "", "")
		require.Equal(t, "evaluated", grpAcc["status"])
		require.Equal(t, true, grpAcc["eligible"])
		require.Equal(t, "group_"+purpose+"_v1", grpAcc["profile"])
		require.Equal(t, false, grpAcc["trigger_row_persisted"])
		require.Equal(t, false, grpAcc["content_attested_by_server"])

		thdAcc := callEvalAccess("req-eval-thd-"+purpose, purpose, 5, f.threadCh, "peer", "9100003", "12", thdDigest)
		require.Equal(t, "evaluated", thdAcc["status"])
		require.Equal(t, true, thdAcc["eligible"])
		require.Equal(t, "thread_"+purpose+"_v1", thdAcc["profile"])
		require.Equal(t, false, thdAcc["trigger_row_persisted"])
		require.Equal(t, false, thdAcc["content_attested_by_server"])
	}

	// 7. Mid-turn asynchronous arrival of the group message row into `message`:
	// - resolve(reply) on the already-minted l1-... reference keeps the exact same header so sameHeader checks never fail!
	// - resolve(contributor) on that l1-... reference now succeeds because the row is persisted and attested.
	// - new bind_live_ingress and evaluate_current_access calls report trigger_row_persisted=true, content_attested_by_server=true.
	grpBytes, _ := json.Marshal(grpPayload)
	f.exec("INSERT INTO message VALUES('9100002',11,'peer','group',2,1700000050,?,0,0)", string(grpBytes))

	resAfterArrivalOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("e", 32),
		"operation":       "resolve",
		"purpose":         "reply",
		"references": []any{
			map[string]any{"delivery_reference": grpLiveDelivRef},
		},
	})))
	require.NoError(t, err)
	resAfterItem := fixtureObject(t, resAfterArrivalOut)["results"].([]any)[0].(map[string]any)
	require.Equal(t, "resolved", resAfterItem["status"])
	require.Equal(t, admitHeaders[grpLiveDelivRef], string(canonical(resAfterItem["header"])), "header must remain byte-identical even after async row arrival mid-turn")

	contribAfterOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("f", 32),
		"operation":       "resolve",
		"purpose":         "contributor",
		"references": []any{
			map[string]any{"delivery_reference": grpLiveDelivRef},
		},
	})))
	require.NoError(t, err)
	contribAfterItem := fixtureObject(t, contribAfterOut)["results"].([]any)[0].(map[string]any)
	require.Equal(t, "resolved", contribAfterItem["status"])

	grpBindPersisted := callBindOp("bind_live_ingress", "req-live-grp-persisted", 2, "group", "9100002", "11", "peer", grpDigest)
	require.Equal(t, "bound", grpBindPersisted["status"])
	require.Equal(t, true, grpBindPersisted["trigger_row_persisted"])
	require.Equal(t, true, grpBindPersisted["content_attested_by_server"])
	require.Equal(t, []any{"admit", "contributor", "reply"}, grpBindPersisted["resolvable_purposes"].([]any))

	grpAccPersisted := callEvalAccess("req-eval-grp-persisted", "admit", 2, "group", "peer", "9100002", "11", grpDigest)
	require.Equal(t, "evaluated", grpAccPersisted["status"])
	require.Equal(t, true, grpAccPersisted["eligible"])
	require.Equal(t, true, grpAccPersisted["trigger_row_persisted"])
	require.Equal(t, true, grpAccPersisted["content_attested_by_server"])

	// 8. Negative persisted-row conflict fixtures:
	// - Payload digest mismatch (e.g. caller spoofed digest or message was edited) -> payload_digest_mismatch
	wrongDigest := sha256OfJSON(map[string]any{"type": 1, "content": "TAMPERED"})
	mismatchBind := callBindOp("bind_live_ingress", "req-live-grp-digest-mismatch", 2, "group", "9100002", "11", "peer", wrongDigest)
	require.Equal(t, "refused", mismatchBind["status"])
	require.Equal(t, "payload_digest_mismatch", mismatchBind["reason"])
	require.Equal(t, true, mismatchBind["trigger_row_persisted"])
	require.Equal(t, false, mismatchBind["content_attested_by_server"])

	mismatchEval := callEvalAccess("req-eval-grp-digest-mismatch", "admit", 2, "group", "peer", "9100002", "11", wrongDigest)
	require.Equal(t, "unavailable", mismatchEval["status"])
	require.Equal(t, "payload_digest_mismatch", mismatchEval["reason"])
	require.Equal(t, true, mismatchEval["trigger_row_persisted"])
	require.Equal(t, false, mismatchEval["content_attested_by_server"])

	// - Identity mismatch (wrong sender or wrong seq compared to stored row) -> identity_mismatch
	idMismatchBind := callBindOp("bind_live_ingress", "req-live-grp-id-mismatch", 2, "group", "9100002", "999", "peer", grpDigest)
	require.Equal(t, "refused", idMismatchBind["status"])
	require.Equal(t, "identity_mismatch", idMismatchBind["reason"])

	// - Revoked row in message_extra -> expired_reference on bind_live_ingress, resolve(l1-...), and evaluate_current_access
	f.exec("INSERT INTO message_extra VALUES('9100002',1,1,0,NULL,'')")
	revokedBind := callBindOp("bind_live_ingress", "req-live-grp-revoked", 2, "group", "9100002", "11", "peer", grpDigest)
	require.Equal(t, "refused", revokedBind["status"])
	require.Equal(t, "expired_reference", revokedBind["reason"])

	revokedResOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("9", 32),
		"operation":       "resolve",
		"purpose":         "reply",
		"references": []any{
			map[string]any{"delivery_reference": grpLiveDelivRef},
		},
	})))
	require.NoError(t, err)
	revokedResItem := fixtureObject(t, revokedResOut)["results"].([]any)[0].(map[string]any)
	require.Equal(t, "unavailable", revokedResItem["status"])
	require.Equal(t, "expired_reference", revokedResItem["reason"])

	revokedEval := callEvalAccess("req-eval-grp-revoked", "reply", 2, "group", "peer", "9100002", "11", grpDigest)
	require.Equal(t, "unavailable", revokedEval["status"])
	require.Equal(t, "expired_reference", revokedEval["reason"])

	// Clean up message 9100002 so we test pure unpersisted negative ACL fixtures next.
	f.exec("DELETE FROM message_extra WHERE message_id='9100002'")
	f.exec("DELETE FROM message WHERE message_id='9100002'")

	// 9. Negative live ACL fixtures with NO trigger row in `message`:
	// - Join-time / clear-history cutoff (channel_offset.message_seq = 15 >= seq 11)
	f.exec("INSERT INTO channel_offset VALUES('bot','group',2,15)")
	offsetBind := callBindOp("bind_live_ingress", "req-live-grp-offset", 2, "group", "9100002", "11", "peer", grpDigest)
	require.Equal(t, "refused", offsetBind["status"])
	require.Equal(t, "visibility_denied", offsetBind["reason"])

	offsetEval := callEvalAccess("req-eval-grp-offset", "admit", 2, "group", "peer", "9100002", "11", grpDigest)
	require.Equal(t, "evaluated", offsetEval["status"])
	require.Equal(t, false, offsetEval["eligible"])
	require.Equal(t, false, offsetEval["predicates"].(map[string]any)["bot_current_read"])
	f.exec("DELETE FROM channel_offset WHERE uid='bot' AND channel_id='group'")

	// - Caller removed from group (group_member.is_deleted = 1)
	f.exec("UPDATE group_member SET is_deleted=1 WHERE group_no='group' AND uid='peer'")
	removedCallerBind := callBindOp("bind_live_ingress", "req-live-grp-removed-caller", 2, "group", "9100002", "11", "peer", grpDigest)
	require.Equal(t, "refused", removedCallerBind["status"])
	require.Equal(t, "visibility_denied", removedCallerBind["reason"])

	removedCallerEval := callEvalAccess("req-eval-grp-removed-caller", "admit", 2, "group", "peer", "9100002", "11", grpDigest)
	require.Equal(t, "evaluated", removedCallerEval["status"])
	require.Equal(t, false, removedCallerEval["eligible"])
	require.Equal(t, false, removedCallerEval["predicates"].(map[string]any)["caller_group_active_member"])
	require.Equal(t, false, removedCallerEval["predicates"].(map[string]any)["caller_current_read"])
	f.exec("UPDATE group_member SET is_deleted=0 WHERE group_no='group' AND uid='peer'")

	// - Bot removed from group (group_member.is_deleted = 1)
	f.exec("UPDATE group_member SET is_deleted=1 WHERE group_no='group' AND uid='bot'")
	removedBotBind := callBindOp("bind_live_ingress", "req-live-grp-removed-bot", 2, "group", "9100002", "11", "peer", grpDigest)
	require.Equal(t, "refused", removedBotBind["status"])
	require.Equal(t, "visibility_denied", removedBotBind["reason"])

	removedBotEval := callEvalAccess("req-eval-grp-removed-bot", "reply", 2, "group", "peer", "9100002", "11", grpDigest)
	require.Equal(t, "evaluated", removedBotEval["status"])
	require.Equal(t, false, removedBotEval["eligible"])
	require.Equal(t, false, removedBotEval["predicates"].(map[string]any)["bot_group_active_member"])
	require.Equal(t, false, removedBotEval["predicates"].(map[string]any)["bot_current_send"])
	f.exec("UPDATE group_member SET is_deleted=0 WHERE group_no='group' AND uid='bot'")

	// - Disbanded group (group.status = 2) denies reply
	f.exec("UPDATE `group` SET status=2 WHERE group_no='group'")
	disbandedEval := callEvalAccess("req-eval-grp-disbanded", "reply", 2, "group", "peer", "9100002", "11", grpDigest)
	require.Equal(t, "evaluated", disbandedEval["status"])
	require.Equal(t, false, disbandedEval["eligible"])
	require.Equal(t, false, disbandedEval["predicates"].(map[string]any)["source_exists"])
	require.Equal(t, false, disbandedEval["predicates"].(map[string]any)["bot_current_send"])
	f.exec("UPDATE `group` SET status=1 WHERE group_no='group'")

	// - Deleted thread (thread.status = 3)
	f.exec("UPDATE thread SET status=3 WHERE group_no=? AND short_id='123456789012345'", f.parent)
	delThreadBind := callBindOp("bind_live_ingress", "req-live-thd-deleted", 5, f.threadCh, "9100003", "12", "peer", thdDigest)
	require.Equal(t, "refused", delThreadBind["status"])
	require.Equal(t, "expired_reference", delThreadBind["reason"])
	f.exec("UPDATE thread SET status=1 WHERE group_no=? AND short_id='123456789012345'", f.parent)

	// - Non-human caller (robot=1) resolves unsupported_principal_v1 with eligible=false
	nonHumanEval := callEvalAccess("req-eval-nonhuman", "admit", 2, "group", "bot", "9100002", "11", grpDigest)
	require.Equal(t, "evaluated", nonHumanEval["status"])
	require.Equal(t, false, nonHumanEval["eligible"])
	require.Equal(t, "unsupported_principal_v1", nonHumanEval["profile"])
}

func TestServerMessageFactsNativeSingleWriterLineageConcurrentLiveIngress(t *testing.T) {
	ctx := t.Context()
	f := newServerFacts(t)
	f.exec("DELETE FROM bot_permission_scope")
	f.exec(NativeAuthorityLineageDDL)
	f.exec(ServerDisclosurePermitDDL)
	f.p.durablePermits = true

	// Replace the synthetic authority with NativeSingleWriterLineageDriver so concurrent
	// BindDeliveredMessage and Facts calls exercise the real single-writer lineage table locking.
	driver, err := NewNativeSingleWriterLineageDriver(NativeSingleWriterLineageConfig{
		Session:       f.s.Session,
		Origin:        fixtureKey.Origin,
		AuthorityID:   "sqlite-single-writer-test",
		Incarnation:   strings.Repeat("a", 32),
		CatalogDigest: fixturePin.Digest,
		StatePath:     filepath.Join(t.TempDir(), "authority-state.json"),
		Key:           []byte(strings.Repeat("m", 32)),
		Provision:     true,
		testNoLocks:   true,
	})
	require.NoError(t, err)
	nativeAuthority, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)
	f.s.Authority = nativeAuthority

	tx, err := f.s.Session.Begin()
	require.NoError(t, err)
	defer tx.RollbackUnlessCommitted()
	anchor, err := f.s.Native.Scope(ctx, tx, fixtureKey, "owner", strings.Repeat("a", 32))
	require.NoError(t, err)
	require.NoError(t, f.s.ProvisionSuffix(ctx, tx, fixtureKey, anchor, fixturePin))
	require.NoError(t, tx.Commit())

	_, err = f.s.Get(ctx, fixtureKey, "owner")
	require.NoError(t, err)

	adapter, err := NewSQLNativeFactAdapter(nativeAuthority, f.p)
	require.NoError(t, err)
	adapter.testNoLocks = true
	c := &config.Context{}
	require.NoError(t, Install(c, f.s, fixturePin, adapter))
	rt := RuntimeFor(c)
	require.NotNil(t, rt)

	digest := sha256OfJSON(map[string]any{"type": 1, "content": "CONCURRENT-LIVE-INGRESS"})

	var wg sync.WaitGroup
	errCh := make(chan error, 24)
	for worker := 0; worker < 6; worker++ {
		w := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iter := 0; iter < 4; iter++ {
				reqID := "conc-bind-" + strconv.Itoa(w) + "-" + strconv.Itoa(iter)
				bindOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
					"schema_version":          json.Number("1"),
					"operation":               "bind_live_ingress",
					"request_id":              reqID,
					"channel_type":            json.Number("2"),
					"channel_id":              "group",
					"message_id":              strconv.Itoa(9500000 + w*100 + iter),
					"message_seq":             strconv.Itoa(100 + w*10 + iter),
					"from_uid":                "peer",
					"observed_payload_sha256": digest,
				})))
				if err != nil {
					errCh <- err
					return
				}
				delivRef := fixtureObject(t, bindOut)["binding"].(map[string]any)["delivery_reference"].(string)
				resReqID := strings.Repeat("a", 30) + strconv.Itoa(w) + strconv.Itoa(iter)
				_, err = rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
					"schema_version":  json.Number("1"),
					"profile_version": json.Number("1"),
					"request_id":      resReqID,
					"operation":       "resolve",
					"purpose":         "admit",
					"references": []any{
						map[string]any{"delivery_reference": delivRef},
					},
				})))
				if err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	// Verify exact single-step SQL authority position allocation and acknowledgement:
	var committedPos, ackedPos, checkpointPos int64
	err = f.s.Session.QueryRow(
		"SELECT committed_position, acknowledged_position, recoverable_scope_checkpoint FROM " + NativeAuthorityLineageTable + " WHERE singleton=1",
	).Scan(&committedPos, &ackedPos, &checkpointPos)
	require.NoError(t, err)
	require.Equal(t, committedPos, ackedPos, "every BindDeliveredMessage and Facts call must acknowledge its exact committed position")
	require.Equal(t, committedPos, checkpointPos)
}

func TestXIN2793SingleStepAuthorityPositionAndCancellationResilience(t *testing.T) {
	ctx := t.Context()
	f := newServerFacts(t)
	f.exec("DELETE FROM bot_permission_scope")
	f.exec(NativeAuthorityLineageDDL)
	f.exec(ServerDisclosurePermitDDL)
	f.p.durablePermits = true

	statePath := filepath.Join(t.TempDir(), "authority-state.json")
	driver, err := NewNativeSingleWriterLineageDriver(NativeSingleWriterLineageConfig{
		Session:       f.s.Session,
		Origin:        fixtureKey.Origin,
		AuthorityID:   "sql-primary",
		Incarnation:   strings.Repeat("a", 32),
		CatalogDigest: fixturePin.Digest,
		StatePath:     statePath,
		Key:           []byte(strings.Repeat("m", 32)),
		Provision:     true,
		testNoLocks:   true,
	})
	require.NoError(t, err)
	nativeAuthority, err := NewFencedAuthorityAdapter(ctx, driver, fixturePin.Digest)
	require.NoError(t, err)
	f.s.Authority = nativeAuthority

	tx, err := f.s.Session.Begin()
	require.NoError(t, err)
	defer tx.RollbackUnlessCommitted()
	anchor, err := f.s.Native.Scope(ctx, tx, fixtureKey, "owner", strings.Repeat("a", 32))
	require.NoError(t, err)
	require.NoError(t, f.s.ProvisionSuffix(ctx, tx, fixtureKey, anchor, fixturePin))
	require.NoError(t, tx.Commit())

	adapter, err := NewSQLNativeFactAdapter(nativeAuthority, f.p)
	require.NoError(t, err)
	adapter.testNoLocks = true
	c := &config.Context{}
	require.NoError(t, Install(c, f.s, fixturePin, adapter))
	rt := RuntimeFor(c)
	require.NotNil(t, rt)

	readLineagePositions := func() (uint64, uint64) {
		var committed, acked int64
		qErr := f.s.Session.QueryRow(
			"SELECT committed_position, acknowledged_position FROM " + NativeAuthorityLineageTable + " WHERE singleton=1",
		).Scan(&committed, &acked)
		require.NoError(t, qErr)
		require.Equal(t, committed, acked)
		return uint64(committed), uint64(acked)
	}
	extractReportedSQLPosition := func(raw []byte) uint64 {
		env := fixtureObject(t, raw)
		for _, item := range env["authorities"].([]any) {
			a := item.(map[string]any)
			if a["kind"] == "sql" {
				pos, pErr := strconv.ParseUint(a["position"].(string), 10, 64)
				require.NoError(t, pErr)
				return pos
			}
		}
		t.Fatal("missing sql authority descriptor")
		return 0
	}

	startCommitted, _ := readLineagePositions()
	digest := sha256OfJSON(map[string]any{"type": 1, "content": "XIN2793-SINGLE-STEP-POS"})

	// 1. BindDeliveredMessage (bind_live_ingress) advances SQL position by exactly 1, and reported position == acknowledged_position.
	bindOut, err := rt.BindDeliveredMessage(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":          json.Number("1"),
		"operation":               "bind_live_ingress",
		"request_id":              "xin2793-pos-bind-1",
		"channel_type":            json.Number("2"),
		"channel_id":              "group",
		"message_id":              "9900001",
		"message_seq":             "50",
		"from_uid":                "peer",
		"observed_payload_sha256": digest,
	})))
	require.NoError(t, err)
	reportedBindPos := extractReportedSQLPosition(bindOut)
	afterBindCommitted, afterBindAcked := readLineagePositions()
	require.Equal(t, startCommitted+1, reportedBindPos)
	require.Equal(t, reportedBindPos, afterBindCommitted)
	require.Equal(t, reportedBindPos, afterBindAcked)

	delivRef := fixtureObject(t, bindOut)["binding"].(map[string]any)["delivery_reference"].(string)

	// 2. Facts (resolve admit) advances SQL position by exactly 1, and reported position == acknowledged_position.
	resOut, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("1", 32),
		"operation":       "resolve",
		"purpose":         "admit",
		"references": []any{
			map[string]any{"delivery_reference": delivRef},
		},
	})))
	require.NoError(t, err)
	reportedResPos := extractReportedSQLPosition(resOut)
	afterResCommitted, afterResAcked := readLineagePositions()
	require.Equal(t, afterBindCommitted+1, reportedResPos)
	require.Equal(t, reportedResPos, afterResCommitted)
	require.Equal(t, reportedResPos, afterResAcked)

	// 3. Canceled caller context during AcquireCurrent/RecordAcknowledgedPosition does NOT brick the driver (d.failed stays false).
	canceledCtx, cancelNow := context.WithCancel(ctx)
	cancelNow()
	txCanceled, err := f.s.Session.Begin()
	require.NoError(t, err)
	_, err = driver.AcquireCurrent(canceledCtx, txCanceled)
	require.ErrorIs(t, err, ErrUnavailable)
	_ = txCanceled.Rollback()

	// Next healthy request succeeds and advances position cleanly by 1.
	res2Out, err := rt.Facts(ctx, fixtureKey, bytes.NewReader(canonical(map[string]any{
		"schema_version":  json.Number("1"),
		"profile_version": json.Number("1"),
		"request_id":      strings.Repeat("2", 32),
		"operation":       "resolve",
		"purpose":         "reply",
		"references": []any{
			map[string]any{"delivery_reference": delivRef},
		},
	})))
	require.NoError(t, err)
	reportedRes2Pos := extractReportedSQLPosition(res2Out)
	afterRes2Committed, afterRes2Acked := readLineagePositions()
	require.Equal(t, afterResCommitted+1, reportedRes2Pos)
	require.Equal(t, reportedRes2Pos, afterRes2Committed)
	require.Equal(t, reportedRes2Pos, afterRes2Acked)
}

