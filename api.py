import os

from intezer_sdk.api import IntezerApiClient

VERSION = '2.0.0'
INTEZER_API_KEY = os.environ.get('INTEZER_API_KEY')
BASE_URL = os.environ.get('INTEZER_BASE_URL', 'https://analyze.intezer.com')
API_BASE = BASE_URL + '/api'
ANALYSES_URL = BASE_URL + '/analyses'


class IntezerAPIException(Exception):
    pass


class InsufficientQuotaException(IntezerAPIException):
    pass


class FileNotAnalyzedException(IntezerAPIException):
    pass


class UnsupportedFileException(IntezerAPIException):
    pass


class Proxy:
    """Thin wrapper around IntezerApiClient for the ida-plugin-report endpoint.

    Uses the official SDK for authentication and HTTP session management,
    but calls the v1-2 plugin-report endpoint directly (not wrapped by the SDK).
    """

    def __init__(self, api_key):
        self._api = IntezerApiClient(
            api_key=api_key,
            base_url=BASE_URL,
            api_version='/api/v2-0',
            user_agent='binja_plugin/{}'.format(VERSION),
        )
        self._authenticated = False

    def _ensure_auth(self):
        if not self._authenticated:
            self._api.authenticate()
            self._authenticated = True

    def _request(self, method, path, base_url=None, **kwargs):
        """Make an authenticated request via the SDK client."""
        self._ensure_auth()
        return self._api.request_with_refresh_expired_access_token(
            method=method,
            path=path,
            base_url=base_url,
            **kwargs,
        )

    def create_plugin_report(self, sha256, file_path=None):
        """Request a block-level report for sha256.

        If 404, auto-submits the file for analysis then retries.
        Returns the result_url string for polling.
        """
        path = '/v1-2/files/{}/ida-plugin-report'.format(sha256)
        response = self._request('POST', path, base_url=API_BASE)

        if response.status_code == 403:
            raise InsufficientQuotaException(
                'Daily quota reached. Contact support@intezer.com.'
            )

        if response.status_code == 404:
            self._submit_for_analysis(sha256, file_path)
            response = self._request('POST', path, base_url=API_BASE)

        if response.status_code == 409:
            raise UnsupportedFileException('File type not supported for Intezer plugin report.')

        if response.status_code != 201:
            response.raise_for_status()

        return response.json()['result_url']

    def _submit_for_analysis(self, sha256, file_path=None):
        try:
            if file_path and os.path.isfile(file_path):
                with open(file_path, 'rb') as fh:
                    response = self._request(
                        'POST',
                        '/analyze',
                        files={'file': (os.path.basename(file_path), fh)},
                    )
            else:
                response = self._request(
                    'POST',
                    '/analyze-by-hash',
                    data={'hash': sha256},
                )

            result_url = response.json()['result_url']
            self.poll_result(result_url, with_api_version=True)
        except Exception:
            raise FileNotAnalyzedException(
                'File not found in Intezer. Analyze it first at {}'.format(BASE_URL)
            )

    def poll_result(self, result_url, with_api_version=False):
        """Poll until job completes. Returns the result dict.

        The SDK client handles retries on connection errors automatically.
        We poll manually since the result_url is a relative path from the API.
        """
        import time

        base = '{}/v2-0/'.format(API_BASE) if with_api_version else API_BASE
        deadline = time.monotonic() + 600  # 10 min timeout

        while True:
            response = self._request('GET', result_url, base_url=base)
            if response.status_code == 202:
                if time.monotonic() > deadline:
                    raise IntezerAPIException(
                        'Intezer analysis timed out waiting for results. '
                        'The job may still be running — try again in a few minutes.'
                    )
                time.sleep(5)
                continue
            response.raise_for_status()
            return response.json()['result']

    def get_analysis_url(self, result_url):
        analysis_id = result_url.split('/')[3]
        return '{}/{}?utm_campaign=binja_plugin'.format(ANALYSES_URL, analysis_id)
