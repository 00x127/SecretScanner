import unittest
import threading
import time
from unittest.mock import MagicMock, patch
from scanner import Scanner

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = Scanner(show_progress=False)

    def test_init(self):
        self.assertEqual(self.scanner.max_threads, 4)
        self.assertIsInstance(self.scanner.lock, type(threading.Lock()))

    @patch('scanner.os.path.isfile')
    @patch('scanner.os.path.getsize')
    @patch('scanner.check_if_binary')
    def test_should_check_file(self, mock_binary, mock_size, mock_isfile):
        mock_isfile.return_value = True
        mock_size.return_value = 100
        mock_binary.return_value = False
        
        self.assertTrue(self.scanner.should_check_file("test.py"))
        
        # Test binary file
        mock_binary.return_value = True
        self.assertFalse(self.scanner.should_check_file("test.exe"))
        
        # Test large file
        mock_binary.return_value = False
        mock_size.return_value = 10 * 1024 * 1024 # 10MB
        self.assertFalse(self.scanner.should_check_file("large.log"))

    def test_check_text_content_concurrency(self):
        # This test attempts to verify thread safety by hammering the method
        # It's not perfect but better than nothing
        
        # Mock patterns to ensure we find something
        with patch('scanner.SECRET_PATTERNS', {
            'TEST_KEY': (r'KEY-[A-Z0-9]{10}', 'high')
        }):
            # Create content that will trigger a match
            content = "This is a secret KEY-ABC1234567 here\n" * 100
            
            def run_scan():
                self.scanner.check_text_content(content, "test_file.txt", "test_file.txt")

            threads = []
            for _ in range(10):
                t = threading.Thread(target=run_scan)
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
            
            # If race condition was present (and logic wasn't idempotent via _id check + lock),
            # we might see duplicates or corruption, but the main goal is no crash
            # and correct deduplication.
            
            # Since the code deduplicates by _id, we should only have 1 result per line per pattern
            # In our mock content, we have 100 lines, so we expect 100 findings total, 
            # regardless of how many threads scanned it.
            
            self.assertEqual(len(self.scanner.results), 100)

if __name__ == '__main__':
    unittest.main()
