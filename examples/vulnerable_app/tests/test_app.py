import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402


class AppTests(unittest.TestCase):
    def test_hash_is_stable_hex(self):
        h = app.hash_password("secret")
        int(h, 16)
        self.assertEqual(h, app.hash_password("secret"))

    def test_find_user(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("create table users(name text)")
        conn.execute("insert into users values ('ann')")
        self.assertEqual(app.find_user(conn, "ann"), [("ann",)])

    def test_calc(self):
        self.assertEqual(app.calc("2+3"), 5)

    def test_add_item(self):
        self.assertEqual(app.add_item(1, []), [1])

    def test_export_not_done(self):
        with self.assertRaises(NotImplementedError):
            app.export_report()


if __name__ == "__main__":
    unittest.main()
