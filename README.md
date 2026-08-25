# happy-wakey-sync

Bounded, local-first Happy Wakey synchronization built on the immutable `opto-sync/syncer.rs` merge engine. The crate exposes one reconciliation policy across Supabase, SQLite, PostgreSQL, and IndexedDB adapters while leaving transport and storage credentials outside the library.

## Authority boundary

Only explicitly client-owned preferences may merge. Identity, provider links, access or refresh tokens, sessions, revocations, roles, factors, recovery, permissions, ownership, and audit state stay server-authoritative. Subjects and replica identities must be derived from verified Shared Auth credentials at the service boundary, never accepted from a sync request body.

Adapters must carry operation IDs and content hashes, persist cursors, use tombstones plus retention watermarks for deletes, and repair from a server cursor after reconnect. Webhooks are wakeups, not authority. NATS Core is at-most-once; durable delivery requires an outbox or JetStream consumer with idempotent settlement.

## Dependency management

Use the released `zed-pkg` CLI as the dependency and script entry point:

```sh
zed validate
zed install --adapter rust
zed run cargo test --all-targets --locked
```

Cargo pins `opto-sync/syncer.rs` and `happy-wakey-interfaces` to immutable reviewed commits. Update the zed manifest, Cargo revisions, cross-backend fixtures, and E2E convergence evidence together.
