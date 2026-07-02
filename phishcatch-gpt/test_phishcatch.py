import unittest
from unittest.mock import patch, MagicMock
from phishcatch import PhishCatch

class TestPhishCatch(unittest.TestCase):

    def setUp(self):
        self.scanner = PhishCatch("google.com")

    def test_generate_permutations(self):
        perms = self.scanner.generate_permutations()
        self.assertIn("gogle.com", perms)  # Omission
        self.assertIn("googlee.com", perms)  # Repetition
        self.assertIn("googel.com", perms)  # Transposition
        self.assertIn("g00g1e.com", perms) # Homoglyphs
        self.assertNotIn("google.com", perms) # Target itself should not be there

    @patch('phishcatch.requests.get')
    def test_check_http_status_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        self.assertTrue(self.scanner.check_http_status("example.com"))

    @patch('phishcatch.requests.get')
    def test_check_http_status_fail(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        self.assertFalse(self.scanner.check_http_status("example.com"))

    @patch('phishcatch.dns.resolver.resolve')
    def test_check_mx_record_success(self, mock_resolve):
        mock_resolve.return_value = True
        self.assertTrue(self.scanner.check_mx_record("example.com"))

    @patch('phishcatch.dns.resolver.resolve')
    def test_check_mx_record_fail(self, mock_resolve):
        mock_resolve.side_effect = Exception("No record")
        self.assertFalse(self.scanner.check_mx_record("example.com"))

if __name__ == '__main__':
    unittest.main()
