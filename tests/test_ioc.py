import unittest

from oif_cyber.ioc import normalize_indicator, normalize_record


class IOCTests(unittest.TestCase):
    def test_domain_normalization(self):
        self.assertEqual(normalize_indicator("domain", "Example.COM."), "example.com")

    def test_ipv4_normalization(self):
        self.assertEqual(normalize_indicator("ipv4", "192.0.2.10"), "192.0.2.10")

    def test_rejects_ipv6_as_ipv4(self):
        with self.assertRaises(ValueError):
            normalize_indicator("ipv4", "2001:db8::1")

    def test_rejects_bad_hash(self):
        with self.assertRaises(ValueError):
            normalize_indicator("sha256", "abcd")

    def test_preserves_provenance(self):
        result = normalize_record({"type": "domain", "value": "EXAMPLE.com", "source": "unit-test"})
        self.assertEqual(result["source"], "unit-test")
        self.assertEqual(len(result["record_fingerprint"]), 64)


if __name__ == "__main__":
    unittest.main()
