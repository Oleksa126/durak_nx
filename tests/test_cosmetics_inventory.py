"""Execute the C inventory grant against real SQLite, including prepared reads.

Build native library with scripts/container_build_verify.sh; run under Linux
with DURAK_INVENTORY_NATIVE_LIB set. No game/user databases are opened.
"""
import ctypes as C
import ctypes.util
import os
import re
import struct
import unittest
from pathlib import Path


@unittest.skipUnless(os.environ.get('DURAK_INVENTORY_NATIVE_LIB'), 'native inventory library required')
class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.native = C.CDLL(os.environ['DURAK_INVENTORY_NATIVE_LIB'], use_errno=True)
        self.sqlite = C.CDLL(ctypes.util.find_library('sqlite3'))
        self.sqlite.sqlite3_open.argtypes = [C.c_char_p, C.POINTER(C.c_void_p)]
        self.sqlite.sqlite3_close.argtypes = [C.c_void_p]
        self.sqlite.sqlite3_exec.argtypes = [C.c_void_p, C.c_char_p, C.c_void_p, C.c_void_p, C.c_void_p]
        self.sqlite.sqlite3_prepare_v2.argtypes = [C.c_void_p, C.c_char_p, C.c_int, C.POINTER(C.c_void_p), C.c_void_p]
        self.sqlite.sqlite3_step.argtypes = [C.c_void_p]
        self.sqlite.sqlite3_finalize.argtypes = [C.c_void_p]
        self.sqlite.sqlite3_column_int.argtypes = [C.c_void_p, C.c_int]
        self.db = C.c_void_p()
        self.assertEqual(self.sqlite.sqlite3_open(b':memory:', C.byref(self.db)), 0)
        self.filename = C.create_string_buffer(b'/switch/durak_nx/metrics.bytes')
        self.filename_fn = C.CFUNCTYPE(C.c_void_p, C.c_void_p, C.c_char_p)(
            lambda db, name: C.addressof(self.filename))
        def resolve(name):
            fn = self.filename_fn if name == b'sqlite3_db_filename' else getattr(self.sqlite, name.decode())
            return C.cast(fn, C.c_void_p).value
        self.resolve = C.CFUNCTYPE(C.c_void_p, C.c_char_p)(resolve)
        self.native.durak_inventory_before_query.argtypes = [C.c_void_p, C.c_char_p, C.c_int, type(self.resolve)]

    def tearDown(self):
        self.assertEqual(self.sqlite.sqlite3_close(self.db), 0)

    def execute(self, sql):
        self.assertEqual(self.sqlite.sqlite3_exec(self.db, sql.encode(), None, None, None), 0, sql)

    def rows(self, sql, columns=1):
        stmt = C.c_void_p()
        self.assertEqual(self.sqlite.sqlite3_prepare_v2(self.db, sql.encode(), -1, C.byref(stmt), None), 0)
        result = []
        while True:
            rc = self.sqlite.sqlite3_step(stmt)
            if rc == 101:
                break
            self.assertEqual(rc, 100)
            result.append(tuple(self.sqlite.sqlite3_column_int(stmt, n) for n in range(columns)))
        self.assertEqual(self.sqlite.sqlite3_finalize(stmt), 0)
        return result

    def create(self, table):
        column = {'avatars': 'dict_avatar_id', 'covers': 'dict_cover_id', 'gadgets': 'dict_gadget_id'}[table]
        extra = ',number INTEGER' if table == 'gadgets' else ''
        self.execute(f'CREATE TABLE "{table}"(id INTEGER PRIMARY KEY AUTOINCREMENT,"{column}" INTEGER{extra})')

    def grant(self, query, length=-1):
        return self.native.durak_inventory_before_query(self.db, query.encode(), length, self.resolve)

    def test_first_prepared_read_sees_all_items(self):
        for table, count in [('covers', 8), ('avatars', 39), ('gadgets', 4)]:
            with self.subTest(table=table):
                self.create(table)
                query = f'SELECT * FROM "{table}"'
                stmt = C.c_void_p()
                self.assertEqual(self.sqlite.sqlite3_prepare_v2(self.db, query.encode(), -1, C.byref(stmt), None), 0)
                self.assertEqual(self.grant(query), 0)
                seen = 0
                while self.sqlite.sqlite3_step(stmt) == 100:
                    seen += 1
                self.assertEqual(self.sqlite.sqlite3_finalize(stmt), 0)
                self.assertEqual(seen, count)

    def test_existing_ids_choices_stats_and_repeat_are_preserved(self):
        self.create('avatars')
        self.execute('INSERT INTO avatars VALUES(90,7)')
        self.execute('CREATE TABLE single_stats(id INTEGER,games INTEGER,wins INTEGER)')
        self.execute('INSERT INTO single_stats VALUES(3,20,11)')
        self.execute('CREATE TABLE var_settings(name TEXT,value INTEGER)')
        self.execute("INSERT INTO var_settings VALUES('current_avatar',7)")
        for _ in range(3):
            self.assertEqual(self.grant('SELECT * FROM avatars'), 0)
        self.assertEqual(self.rows('SELECT count(*),count(DISTINCT dict_avatar_id) FROM avatars', 2), [(39,39)])
        self.assertEqual(self.rows('SELECT id FROM avatars WHERE dict_avatar_id=7'), [(90,)])
        self.assertEqual(self.rows('SELECT games,wins FROM single_stats',2), [(20,11)])
        self.assertEqual(self.rows('SELECT value FROM var_settings'), [(7,)])

    def test_gadget_floor_preserves_positive_stock_and_identity(self):
        self.create('gadgets')
        self.execute('INSERT INTO gadgets VALUES(11,1,7),(12,2,0),(13,3,-2),(99,99,0)')
        self.assertEqual(self.grant('SELECT * FROM gadgets'), 0)
        self.assertEqual(self.rows('SELECT id,number FROM gadgets WHERE id IN(11,12,13) ORDER BY id',2),
                         [(11,7),(12,1),(13,1)])
        self.assertEqual(self.rows('SELECT count(*) FROM gadgets WHERE dict_gadget_id BETWEEN 1 AND 4'), [(4,)])
        self.assertEqual(self.rows('SELECT number FROM gadgets WHERE dict_gadget_id=99'), [(0,)])

    def test_other_databases_and_sql_are_untouched(self):
        self.create('avatars')
        for filename in [b'/switch/durak_nx/dict.bytes', b'/switch/another/metrics.bytes']:
            self.filename = C.create_string_buffer(filename)
            self.assertEqual(self.grant('SELECT * FROM avatars'), 0)
        self.filename = C.create_string_buffer(b'/switch/durak_nx/metrics.bytes')
        for query in ['SELECT 1', 'PRAGMA table_info(avatars)', 'UPDATE avatars SET id=1',
                      "SELECT 'FROM avatars'", 'SELECT * FROM attached.avatars']:
            self.assertEqual(self.grant(query), 0)
        self.assertEqual(self.rows('SELECT count(*) FROM avatars'), [(0,)])

    def test_quoted_names_comments_and_explicit_length(self):
        self.create('covers')
        query = '/* FROM avatars */ SELECT "from" FROM main.[covers] -- ignore'
        self.assertEqual(self.grant(query, len(query)), 0)
        self.assertEqual(self.rows('SELECT count(*) FROM covers'), [(8,)])
        self.create('avatars')
        self.assertEqual(self.grant('SELECT 1 FROM avatars', 8), 0)
        self.assertEqual(self.rows('SELECT count(*) FROM avatars'), [(0,)])

    def test_missing_or_incompatible_schema_is_not_created_or_replaced(self):
        self.assertEqual(self.grant('SELECT * FROM avatars'), 21)
        self.assertEqual(self.rows("SELECT count(*) FROM sqlite_master WHERE name='avatars'"), [(0,)])
        self.execute('CREATE TABLE avatars(id INTEGER PRIMARY KEY,wrong_column INTEGER)')
        self.execute('INSERT INTO avatars VALUES(5,9)')
        self.assertEqual(self.grant('SELECT * FROM avatars'), 21)
        self.assertEqual(self.rows('SELECT id,wrong_column FROM avatars',2), [(5,9)])

    def test_sqlite_write_error_is_returned_and_grant_rolls_back(self):
        self.create('gadgets')
        self.execute('INSERT INTO gadgets VALUES(11,2,0)')
        self.execute("CREATE TRIGGER deny_floor BEFORE UPDATE OF number ON gadgets BEGIN SELECT RAISE(ABORT,'floor denied'); END")
        self.assertEqual(self.grant('SELECT * FROM gadgets'), 19)
        self.assertEqual(self.rows('SELECT id,dict_gadget_id,number FROM gadgets',3), [(11,2,0)])

    def test_readonly_error_is_preserved(self):
        self.create('covers')
        self.execute('PRAGMA query_only=ON')
        self.assertEqual(self.grant('SELECT * FROM covers'), 8)
        self.assertEqual(self.rows('SELECT count(*) FROM covers'), [(0,)])

    def test_grant_respects_outer_transaction_and_errno(self):
        self.create('covers')
        self.execute('BEGIN')
        C.set_errno(123)
        self.assertEqual(self.grant('SELECT * FROM covers'), 0)
        self.assertEqual(C.get_errno(), 123)
        self.assertEqual(self.rows('SELECT count(*) FROM covers'), [(8,)])
        self.execute('ROLLBACK')
        self.assertEqual(self.rows('SELECT count(*) FROM covers'), [(0,)])

    def test_patch_changes_only_quantity_instruction_and_fails_closed(self):
        header = (Path(__file__).resolve().parents[1] / 'include/region_patch.h').read_text()
        words = header.split('DURAK_GADGET_STOCK_CONTEXT[] = {')[1].split('};')[0]
        context = struct.pack('<12I', *[int(x,16) for x in re.findall(r'0x[0-9a-f]+', words)])
        rva = 0xd67690
        memory = C.create_string_buffer(rva+len(context))
        C.memmove(C.addressof(memory)+rva, context, len(context))
        for fn in ['durak_patch_gadget_stock','durak_verify_gadget_stock']:
            getattr(self.native,fn).argtypes=[C.c_void_p,C.c_size_t]
        self.assertEqual(self.native.durak_patch_gadget_stock(memory,len(memory)),0)
        actual = memory.raw[rva:rva+len(context)]
        expected = context[:20]+struct.pack('<I',0x71000129)+context[24:]
        self.assertEqual(actual,expected)
        self.assertEqual(self.native.durak_verify_gadget_stock(memory,len(memory)),0)
        C.memmove(C.addressof(memory)+rva,context,len(context))
        memory[rva+8]=b'\0'
        before=memory.raw[rva:rva+len(context)]
        self.assertEqual(self.native.durak_patch_gadget_stock(memory,len(memory)),-2)
        self.assertEqual(memory.raw[rva:rva+len(context)],before)


if __name__ == '__main__':
    unittest.main()
