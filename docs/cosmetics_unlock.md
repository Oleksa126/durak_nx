# Local cosmetics and unlimited gadgets

Scope: Durak 25.0 local inventory only. The accepted v0.1.0 tag remains unchanged.
No purchase receipts, premium flags, remote account state or statistics are altered.

## Evidence

`scripts/verify_cosmetics_unlock.py` reads the original bundle and metadata,
resolves Assembly-CSharp through target relocations and verifies:

- Dictionary catalog: covers IDs 1..8, avatars 1..39, gadgets 1..4.
- All 51 corresponding Sprite assets are present in the original bundle.
- Ownership property contracts: MetricsTypes.covers.dict_cover_id,
  MetricsTypes.avatars.dict_avatar_id, MetricsTypes.gadgets.dict_gadget_id/number.
- GadgetSelectWindow.useGadget token 0x06000416 resolves to RVA 0xd67434.
  MetricsTypes.gadgets.get_number at 0xdb6854 reads offset 0x1c.
- The 12-word instruction fingerprint at 0xd67690 verifies item matching,
  quantity read/subtract/check/store and the original database update call.
  Only RVA 0xd676a4 changes from `subs w9,w9,#1` to `subs w9,w9,#0`.
  The original GameManager.UseGadget call at 0xd67720 remains intact.
- Existing hardware log 22 identifies the metrics filename as
  `/switch/durak_nx/metrics.bytes`; previous serialized bindings identify
  its DataManager namespace as MetricsTypes.

## Implementation

The SQLite prepare wrapper first executes the original prepare. Its errors are
returned unchanged. On a successful SELECT from an inventory table, before
the first sqlite3_step, it grants missing entries on that same connection.
Both known metrics filename forms are allowed; other databases are untouched.
Preparing the SELECT before granting preserves native missing-table errors,
and granting before stepping lets the game's first read populate its cache
with the full inventory.

PRAGMA table_info must confirm the existing INTEGER primary-key id, exact
item column and gadget number column before writes. The wrapper does not
create schema or replace the database. A nested-safe savepoint inserts only
missing catalog IDs without touching existing row IDs or selected settings.
Gadgets with NULL/zero/negative stock receive one; positive stock is retained.
The verified instruction patch then prevents consumption, leaving the game's
quantity display stable, including any existing larger quantities.

Write errors preserve native SQLite return codes and errno; logs capture the
extended code and message before rollback can replace the connection error.
The grant rolls back on failure, and the failed prepared read is finalized
and reports failure instead of continuing with a partially granted inventory.
Only schema validation and missing API contracts produce a wrapper MISUSE.

## Validation

Ten native-library tests execute the C helper against real host SQLite:
prepared reads observe all items; IDs, selection and statistics survive;
repeat grants are idempotent; positive quantities are retained; foreign paths,
SQL comments, quoting and explicit lengths are handled; unexpected schema is
rejected; readonly and trigger/constraint errors are returned; partial grants
roll back; outer transactions and errno are preserved. Patch tests verify
that only one instruction changes and mismatches cause no partial patch.
The pinned build also runs existing native and 12 Python loader checks.

Status: NEEDS_HARDWARE_TEST. Copy the current `build/switch/` to the SD root,
merging folders. On Switch, open each selector, choose an item, restart and
confirm the selection remains. Use each gadget repeatedly and confirm its
effect executes without reducing the count. Inspect `[INVENTORY]` grants
and `[INVENTORY ERROR]` diagnostics in durak_nx.log if a selector stays locked.
