//! The ledger must use the locked SQLite source, rather than a host OS library.
#[test]
fn ledger_sqlite_matches_the_pinned_bundled_source() {
    assert_eq!(rusqlite::version(), "3.54.1");
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    let source_id: String = connection
        .query_row("SELECT sqlite_source_id()", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        source_id,
        "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76"
    );
}
