import unittest

from hosts import extract_hosts


class TestExtractHosts(unittest.TestCase):

    def test_ip(self):
        self.assertEqual(extract_hosts(
            "192.168.1.1"), ["192.168.1.1"])

    def test_cidr(self):
        self.assertEqual(extract_hosts(
            "192.168.1.0/30"), ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(extract_hosts(
            "10.0.0.0/29"), ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"])

    def test_domain(self):
        self.assertEqual(extract_hosts(
            "www.example.com"), ["www.example.com"])
        self.assertEqual(extract_hosts(
            "www.example.com:8080"), ["www.example.com"])
        self.assertEqual(extract_hosts(
            "www.example.com/10"), ["www.example.com"])
        self.assertEqual(extract_hosts(
            "x.x.x.x.com"), ["x.x.x.x.com"])

    def test_url(self):
        self.assertEqual(extract_hosts(
            "https://www.example.com/path"), ["www.example.com"])
        self.assertEqual(extract_hosts(
            "ftp://example.com/path"), ["example.com"])
        self.assertEqual(extract_hosts(
            "http://17.0.0.0/10"), ["17.0.0.0"])

    def test_email(self):
        self.assertEqual(extract_hosts(
            "x@x.com"), ["x.com"])

    def test_none(self):
        self.assertEqual(extract_hosts(
            "x!x"), [])


if __name__ == "__main__":
    unittest.main()
