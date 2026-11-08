"""First-download responsive, focus and error-state browser acceptance."""
import unittest
from tests.helpers.update_download_browser import layout

class DownloadLayoutTests(unittest.TestCase):
    def test_responsive_download_layout(self):
        layout()

if __name__ == '__main__':
    unittest.main()
