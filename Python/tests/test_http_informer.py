import unittest
from types import SimpleNamespace
from unittest.mock import patch

from relayinformer.informers.HttpInformer import HttpInformer


class HttpInformerTests(unittest.TestCase):
    def test_init_preserves_url_without_trimming_trailing_slash(self):
        informer = HttpInformer("https://pki.domain.local/certsrv/", "domain/user")

        self.assertEqual(informer.url, "https://pki.domain.local/certsrv/")

    @patch("relayinformer.informers.HttpInformer.requests.get")
    def test_verify_ntlm_required_follows_redirect_and_updates_target_url(self, mock_get):
        mock_get.return_value = SimpleNamespace(
            status_code=401,
            headers={"WWW-Authenticate": "Negotiate, NTLM"},
            url="https://pki.domain.local/certsrv/",
        )
        informer = HttpInformer("https://pki.domain.local/certsrv", "domain/user")

        result = informer.verify_ntlm_required()

        self.assertTrue(result)
        self.assertEqual(informer.url, "https://pki.domain.local/certsrv/")
        mock_get.assert_called_once_with(
            "https://pki.domain.local/certsrv", verify=False, allow_redirects=True
        )

    @patch("relayinformer.informers.HttpInformer.requests.get")
    def test_verify_ntlm_required_rejects_non_authenticating_endpoint(self, mock_get):
        mock_get.return_value = SimpleNamespace(
            status_code=200,
            headers={},
            url="https://pki.domain.local/",
        )
        informer = HttpInformer("https://pki.domain.local/", "domain/user")

        result = informer.verify_ntlm_required()

        self.assertFalse(result)

    @patch("relayinformer.informers.HttpInformer.logger.error")
    @patch("relayinformer.informers.HttpInformer.requests.get")
    def test_verify_ntlm_required_suggests_host_root_adcs_path(self, mock_get, mock_error):
        mock_get.return_value = SimpleNamespace(
            status_code=404,
            headers={},
            url="http://10.112.0.140/certsv",
        )
        informer = HttpInformer("http://10.112.0.140/certsv", "domain/user")

        result = informer.verify_ntlm_required()

        self.assertFalse(result)
        self.assertIn(
            "--url http://10.112.0.140/certsrv/",
            mock_error.call_args[0][0],
        )

    @patch("relayinformer.informers.HttpInformer.requests.get")
    def test_verify_ntlm_required_rejects_non_ntlm_auth(self, mock_get):
        mock_get.return_value = SimpleNamespace(
            status_code=401,
            headers={"WWW-Authenticate": "Basic realm=certsrv"},
            url="https://pki.domain.local/certsrv/",
        )
        informer = HttpInformer("https://pki.domain.local/certsrv", "domain/user")

        result = informer.verify_ntlm_required()

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
