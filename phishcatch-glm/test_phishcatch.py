import unittest
from phishcatch import PhishCatchGLM

class TestPhishCatchGLM(unittest.TestCase):
    def test_permutations(self):
        scanner = PhishCatchGLM("test.com")
        perms = scanner.get_permutations()
        self.assertIn("tst.com", perms)
        self.assertIn("teest.com", perms)
        
if __name__ == '__main__':
    unittest.main()
