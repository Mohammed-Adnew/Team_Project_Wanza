"""Unit tests for URL parsing, authentication evidence, and consent-gated uploads."""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from config import Config
from detection import attachment_check
from detection.link_check import extract_urls, get_url_domain, check_url_safe_browsing
from detection.sender_auth import summarize_authentication_results
from detection.text_check import extract_domain_from_email, normalize_domain


class DetectionSafetyTests(unittest.TestCase):
    def setUp(self):
        self.original_api_key = Config.VT_API_KEY
        self.original_upload_setting = Config.VT_FILE_UPLOAD_ENABLED
        self.original_sb_key = Config.SAFE_BROWSING_API_KEY

    def tearDown(self):
        Config.VT_API_KEY = self.original_api_key
        Config.VT_FILE_UPLOAD_ENABLED = self.original_upload_setting
        Config.SAFE_BROWSING_API_KEY = self.original_sb_key

    def test_url_parser_uses_hostname_not_credentials_or_port(self):
        self.assertEqual(get_url_domain("https://paypal.com.attacker.net@evil.example:9443/login"), "evil.example")
        self.assertEqual(get_url_domain("https://xn--bcher-kva.example./path"), "xn--bcher-kva.example")
        self.assertEqual(get_url_domain("javascript:alert(1)"), "")

    def test_url_extraction_trims_punctuation_and_deduplicates(self):
        self.assertEqual(extract_urls("See https://example.com/path), and https://example.com/path."), ["https://example.com/path"])

    def test_sender_domain_normalization_handles_mailbox_and_port(self):
        self.assertEqual(extract_domain_from_email('Help Desk <alerts@Example.COM.>'), "example.com")
        self.assertEqual(normalize_domain("https://user:pass@Example.com:443/a"), "example.com")

    def test_authentication_results_are_reported_but_not_asserted_as_verified(self):
        reasons = summarize_authentication_results(["mx.example; spf=pass; dkim=pass; dmarc=fail"])
        self.assertTrue(any("DMARC FAIL" in reason for reason in reasons))
        self.assertTrue(any("not independently verified" in reason for reason in reasons))

    def test_unknown_hash_is_not_uploaded_without_consent(self):
        Config.VT_API_KEY = "test-key"
        Config.VT_FILE_UPLOAD_ENABLED = True
        response = Mock(status_code=404)
        with patch.object(attachment_check.requests, "get", return_value=response), \
             patch.object(attachment_check.requests, "post") as upload:
            status, _reason = attachment_check.check_virustotal_hash(
                "a" * 64, file_bytes=b"demo sample", filename="sample.txt", allow_upload=False,
            )
        self.assertEqual(status, "unknown")
        upload.assert_not_called()

    def test_unknown_hash_upload_requires_server_flag_and_consent(self):
        Config.VT_API_KEY = "test-key"
        Config.VT_FILE_UPLOAD_ENABLED = True
        missing = Mock(status_code=404)
        accepted = Mock()
        accepted.raise_for_status.return_value = None
        accepted.json.return_value = {"data": {"id": "analysis-id"}}
        with patch.object(attachment_check.requests, "get", return_value=missing), \
             patch.object(attachment_check.requests, "post", return_value=accepted) as upload:
            status, _reason = attachment_check.check_virustotal_hash(
                "a" * 64, file_bytes=b"demo sample", filename="sample.txt", allow_upload=True,
            )
        self.assertEqual(status, "pending")
        upload.assert_called_once()

    def test_attachment_without_bytes_is_labeled_filename_only(self):
        Config.VT_API_KEY = ""
        result = attachment_check.check_attachment("report.pdf")
        self.assertTrue(any("filename extension only" in reason for reason in result["reasons"]))

    def test_user_consent_is_not_enough_when_server_upload_flag_is_off(self):
        Config.VT_API_KEY = "test-key"
        Config.VT_FILE_UPLOAD_ENABLED = False
        with patch.object(attachment_check.requests, "get", return_value=Mock(status_code=404)), \
             patch.object(attachment_check.requests, "post") as upload:
            status, _reason = attachment_check.check_virustotal_hash(
                "b" * 64, file_bytes=b"demo sample", filename="sample.txt", allow_upload=True,
            )
        self.assertEqual(status, "unknown")
        upload.assert_not_called()

    def test_safe_browsing_missing_key_is_explicitly_skipped(self):
        Config.SAFE_BROWSING_API_KEY = ""
        flagged, reason, status = check_url_safe_browsing("https://example.com")
        self.assertFalse(flagged)
        self.assertEqual(status, "not_configured")
        self.assertIn("skipped", reason)


if __name__ == "__main__":
    unittest.main()
