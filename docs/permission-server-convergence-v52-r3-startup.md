# Permission Server Convergence (`v52-r3-startup` — `XIN-2858` Bounded Native Startup Repair)

## 1. Governance & Scope Boundary

- **Task**: `XIN-2793` (`6a92a547-cb82-4c3d-ac6c-8f5529028ba4`)
- **Author / Fork / Branch / Target**: `boris-clark` / `feat/xin-2793-permission-server` -> `Mininglamp-OSS/octo-server:chore/mcp-integration-20261103` (`79701d4912eba79a8bcb02c58ed86609c38335e2`), advancing from Round 3 approved pin `f3cf3a13a29c3f85be14e4b794d1a0836b54a9dc`
- **Authorization**: Owner `2122964206335463424`, Charter receipt `65ac8fad-1356-4f0b-a2d2-fe55bab0111e`, `XIN-2858` preflight outcome `b7a0d0d2-b7ff-4161-b83e-be825b3b6024`, and `XIN-2834` Round 3 baseline verdict `26710b0b-d90f-4809-a06e-8cc4a14557d7`
- **Bounded Profile**: Single existing native writer with uninterrupted durable store lineage across normal process restart (`OCTO_PERMISSION_BUNDLE_AUTHORITY_MODE=native_single_writer_lineage_v1`), no concurrent writer, no HA failover, and no point-in-time restore recovery claim.

---

## 2. Concrete Startup Gap Resolved (`XIN-2858` `b7a0d0d2`)

### 2.1 Preflight Finding in `XIN-2858`
At `f3cf3a13a29c3f85be14e4b794d1a0836b54a9dc`, `main.go:617-618` invoked `permissionbundle.InstallFromEnvWithHooks(ctx, nil, nil, message.NewServerMessageFactHooks(ctx))` while `pkg/permissionbundle/install.go:158-167` required a non-nil `AuthorityDriver` whenever `OCTO_PERMISSION_BUNDLE_ENABLED=true`. Task-owned MySQL and environment configuration could not supply an entrypoint authority binding.

### 2.2 Bounded Native Single-Writer Lineage Authority (`AuthorityModeNativeSingleWriterV1`)
1. **`pkg/permissionbundle/authority_fence.go`**:
   - Added `AuthorityModeNativeSingleWriterV1 = "native_single_writer_lineage_v1"` to `RejectUnfencedAuthorityMode` while keeping `""`, `"none"`, `"disabled"`, `"sql_read_only_variables"`, `"same_db_counter"`, `"unverified_pool"`, and all unfenced substitutes rejected with `ErrUnavailable`.
   - Implemented `NativeSingleWriterLineageDriver` (`NewNativeSingleWriterLineageDriver`) backed by:
     - Durable SQL lineage table `bot_permission_authority_lineage` (`NativeAuthorityLineageDDL`, singleton row `singleton = 1` storing `authority_id`, 32-hex `incarnation`, 64-hex `catalog_digest`, `election_generation`, 32-hex `active_writer_id`, `committed_position`, `acknowledged_position`, `recoverable_scope_checkpoint`, and 64-hex `state_hmac`).
     - Exclusive host-side durable state file (`OCTO_PERMISSION_BUNDLE_AUTHORITY_STATE_PATH`, regular file, mode `0600`, no symlinks, `fsync`-persisted via atomic temp-file rename) storing the HMAC-SHA256 authenticated checkpoint (`authority_id`, `incarnation`, `catalog_digest`, `election_generation`, `active_writer_id`, `min_ack_position`, `recoverable_scope_checkpoint`, `state_hmac`).
     - Startup and post-migration full-table integrity verification (`verifyScopeTableInTx`) over `bot_permission_scope`, verifying every row's `bundle_digest`, `native_anchor_digest`, and `native_anchor_json.authority_incarnation == incarnation`.
   - **Startup / Normal-Restart / Fail-Closed Semantics**:
     - **Fresh Bootstrap (`OCTO_PERMISSION_BUNDLE_AUTHORITY_PROVISION=true`)**: Only permitted when both `AuthorityStatePath` and `bot_permission_authority_lineage` are absent and `bot_permission_scope` has `0` rows. Creates `bot_permission_authority_lineage` (and `bot_permission_disclosure_permit` when `OCTO_PERMISSION_BUNDLE_DURABLE_PERMIT_LEDGER=true`), initializes `election_generation = 1`, `position = 1`, and a cryptographic 32-hex `active_writer_id`, and persists the `0600` HMAC-authenticated host state file.
     - **Normal Process Restart (`OCTO_PERMISSION_BUNDLE_AUTHORITY_PROVISION=false` or `true`)**: When both `AuthorityStatePath` and `bot_permission_authority_lineage` exist, verifies both HMACs, verifies exact `authority_id`, `incarnation`, and `catalog_digest` agreement, verifies `sql.election_generation >= host.election_generation` and `sql.acknowledged_position >= host.min_ack_position >= scope_count + 1`, verifies all `bot_permission_scope` rows, increments `election_generation` (`N -> N+1`), rotates `active_writer_id` (fencing out any prior writer session), and preserves uninterrupted `incarnation` and monotonic `position`s.
     - **Per-Transaction Guarantees**:
       - `AcquireCurrent(ctx, tx)`: verifies both `AuthorityStatePath` and `bot_permission_authority_lineage` inside the caller's `RepeatableRead` `*dbr.Tx` (`FOR SHARE NOWAIT`), checks `active_writer_id` and `election_generation`, and allocates a strictly monotonic position.
       - `AssertCurrent(ctx, tx, session)`: re-verifies `AuthorityStatePath` and `bot_permission_authority_lineage` inside `tx` immediately before `tx.Commit()`.
       - `RecordAcknowledgedPosition(ctx, session)`: after `tx.Commit()`, executes an atomic SQL CAS update on `bot_permission_authority_lineage` (`WHERE singleton=1 AND authority_id=? AND incarnation=? AND active_writer_id=? AND election_generation=? AND state_hmac=?`) and atomically `fsync`s the updated checkpoint to `AuthorityStatePath`.
     - **Explicit Refusals (Never Faked)**:
       - Missing state when `AuthorityProvision=false` -> `ErrUnavailable`
       - Missing `AuthorityStatePath` when `bot_permission_authority_lineage` or `bot_permission_scope` rows exist (journal loss) -> `ErrUnavailable` (even if `AuthorityProvision=true`)
       - Missing `bot_permission_authority_lineage` when `AuthorityStatePath` exists (DB wipe) -> `ErrUnavailable`
       - SQL `acknowledged_position` or `election_generation` behind `AuthorityStatePath` (stale DB restore / rollback) -> `ErrUnavailable`
       - Wrong `incarnation`, wrong `authority_id`, wrong `catalog_digest`, wrong HMAC key, tampered SQL/file state, symlink, or permissive file mode (`mode & 0077 != 0`) -> `ErrUnavailable`
       - Superseded/concurrent writer session (`active_writer_id` or `election_generation` mismatch) -> `ErrUnavailable` / `ErrReconcile`

2. **`pkg/permissionbundle/install.go`, `pkg/permissionbundle/store.go`, `pkg/permissionbundle/native_wire.go`, & `main.go`**:
   - Wired `AuthorityModeNativeSingleWriterV1` in `InstallFromEnvWithHooks` and `InstallOptIn`, and added `VerifyAfterSetup(ctx)` in `main.go` immediately after `module.Setup(ctx)` so post-migration table state is verified before serving traffic.
   - Enabled `store.requireProvisionedScopeOnFacts = true` in `AuthorityModeNativeSingleWriterV1` so both `Runtime.Facts` (`POST /v1/bot/permission-facts/v1`) and `Runtime.BindDeliveredMessage` (`POST /v1/bot/permission-facts/v1/bind-delivery`) verify an existing, non-retired, digest-valid `bot_permission_scope` row anchored to the current `authority_incarnation` inside the `RepeatableRead` transaction (never auto-provisioning on read/recovery).

---

## 3. Minimum Authenticated Current-State / Recovery Contract for Agent (`XIN-2795`)

No new unapproved route or schema delta is needed; the existing checked `bf_`-authenticated endpoints provide the complete current-state and authority-lineage recovery proof:

1. **Current Policy & Scope Anchor Verification**:
   - `GET /v1/bot/permission-bundle/v1?space_id=<space_id>` (`Authorization: Bearer bf_...`)
   - Runs under `RepeatableRead` SQL transaction (`Store.begin` -> `Authority.Begin` -> `Native.Scope` -> `Store.read("SHARE")` -> `complete`), verifying active native principals/membership, active `NativeSingleWriterLineageDriver` lease/checkpoint, and a non-retired `bot_permission_scope` row whose `native_anchor_json.authority_incarnation` matches the active SQL authority `incarnation`. Returns `200 OK` with canonical `Bundle` JSON (`key`, `scope_incarnation`, `revision`, `context_epoch`, `catalog_version`, `catalog_digest`, `bundle_digest`, `invocation`, `capability`).
2. **Authenticated 2-Authority (`sql` + `im`) Lineage Cut Verification**:
   - `POST /v1/bot/permission-facts/v1?space_id=<space_id>` (`Authorization: Bearer bf_...`)
   - Request body: schema-valid `ResolveRequest` (`{"schema_version":1,"profile_version":1,"request_id":"<32-hex>","operation":"resolve","purpose":"admit","references":[{"delivery_reference":"s1-1-00-1-0"}]}`) or `HistoryDisclosureRequest`.
   - Under `AuthorityModeNativeSingleWriterV1`, `Runtime.Facts` enforces `verifyProvisionedScope` (`Store.read("SHARE")` on `bot_permission_scope` + `catalogMembers`) in the same `RepeatableRead` transaction before `SQLNativeFactAdapter.Read`, validates both `sql` and `im` cuts (`ValidateCuts`), and returns `200 OK` with the 2-element `authorities` array (`kind: "sql"` and `kind: "im"`, each carrying `authority_id`, 32-hex `incarnation`, monotonic `position`, 32-hex `read_nonce`, and `consistency: "ack_before_read_start"`).
   - Missing/retired/corrupt `bot_permission_scope`, departed member, deactivated space/bot, wrong incarnation, or lost/regressed authority state returns `HTTP 400` (`ErrUnavailable` / `ErrForbidden`).
