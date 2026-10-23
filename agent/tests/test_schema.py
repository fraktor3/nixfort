import unittest

from nixfort_agent.errors import Rejected
from nixfort_agent.schema import Bool, Int, IPv4, IPv4OrCIDR, ListOf, Nullable, Obj, Str


class SchemaTests(unittest.TestCase):
    def test_str(self):
        s = Str(max_len=5, pattern=r"[a-z]+")
        self.assertEqual(s.validate("abc", "x"), "abc")
        for bad in ("abcdef", "ab1", "a\nb", 5, None):
            with self.assertRaises(Rejected):
                s.validate(bad, "x")

    def test_int_rejects_bool_and_float(self):
        i = Int(1, 10)
        self.assertEqual(i.validate(3, "x"), 3)
        for bad in (True, 3.0, "3", 0, 11):
            with self.assertRaises(Rejected):
                i.validate(bad, "x")

    def test_bool(self):
        self.assertIs(Bool().validate(False, "x"), False)
        with self.assertRaises(Rejected):
            Bool().validate(0, "x")

    def test_ipv4(self):
        self.assertEqual(IPv4().validate("10.0.0.1", "x"), "10.0.0.1")
        for bad in ("10.0.0.256", "::1", "10.0.0.0/24", "010.0.0.1x"):
            with self.assertRaises(Rejected):
                IPv4().validate(bad, "x")

    def test_cidr_strict(self):
        self.assertEqual(IPv4OrCIDR().validate("10.88.0.0/24", "x"), "10.88.0.0/24")
        with self.assertRaises(Rejected):
            IPv4OrCIDR().validate("10.88.0.1/24", "x")

    def test_list(self):
        lst = ListOf(Int(1, 5), max_len=2, unique=True)
        self.assertEqual(lst.validate([1, 2], "x"), [1, 2])
        for bad in ([1, 2, 3], [1, 1], "1,2"):
            with self.assertRaises(Rejected):
                lst.validate(bad, "x")

    def test_obj_unknown_and_missing(self):
        o = Obj({"a": Int(1, 2), "b": Nullable(Str())}, optional=frozenset({"b"}))
        self.assertEqual(o.validate({"a": 1}), {"a": 1})
        for bad in ({"a": 1, "c": 1}, {}, [], {"a": 1, "b": 5}):
            with self.assertRaises(Rejected):
                o.validate(bad)


if __name__ == "__main__":
    unittest.main()
