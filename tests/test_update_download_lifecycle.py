"""First-download access, cancellation, retry and cleanup browser acceptance."""
import unittest
from tests.helpers.update_download_browser import lifecycle

class DownloadLifecycleTests(unittest.TestCase):
    def test_private_download_lifecycle(self):
        lifecycle()

if __name__ == '__main__':
    unittest.main()
