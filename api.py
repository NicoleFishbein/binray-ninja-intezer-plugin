import os
from urllib.parse import urljoin

import requests
import requests.adapters
import tenacity

VERSION = '1.0.0'
INTEZER_API_KEY = os.environ.get('INTEZER_API_KEY')
BASE_URL = os.environ.get('INTEZER_BASE_URL', 'https://analyze.intezer.com')
API_URL = urljoin(BASE_URL, '/api')
API_VERSION = 'v2-0'
ANALYSES_URL = urljoin(BASE_URL, '/analyses')

URLS = {
    'get_access_token': '{}/{}/get-access-token'.format(API_URL, API_VERSION),
    'create_plugin_report': '{}/v1-2/files/{{}}/ida-plugin-report'.format(API_URL),
    'analyze_file': '{}/{}/analyze'.format(API_URL, API_VERSION),
    'analyze_hash': '{}/{}/analyze-by-hash'.format(API_URL, API_VERSION),
}


class IntezerAPIException(Exception):
    pass


class InsufficientQuotaException(IntezerAPIException):
    pass


class FileNotAnalyzedException(IntezerAPIException):
    pass


class UnsupportedFileException(IntezerAPIException):
    pass


class Proxy:
    def __init__(self, api_key):
        self._api_key = api_key
        self._session = None

    @property
    def session(self):
        if not self._session:
            session = requests.Session()
            session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
            session.mount('http://', requests.adapters.HTTPAdapter(max_retries=3))
            session.headers['User-Agent'] = 'binja_plugin/{}'.format(VERSION)
            self._session = session
        return self._session

    def _init_access_token(self):
        if 'Authorization' not in self.session.headers:
            response = requests.post(URLS['get_access_token'], json={'api_key': self._api_key})
            if response.status_code == 401:
                raise IntezerAPIException(
                    'Invalid API key (401). Check your INTEZER_API_KEY environment variable.'
                )
            response.raise_for_status()
            token = 'Bearer {}'.format(response.json()['result'])
            self.session.headers['Authorization'] = token

    _RETRY_ON = (requests.exceptions.ConnectionError, requests.exceptions.Timeout)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(_RETRY_ON),
        stop=tenacity.stop_after_attempt(2),
    )
    def _post(self, url, **kwargs):
        self._init_access_token()
        return self.session.post(url, **kwargs)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(_RETRY_ON),
        stop=tenacity.stop_after_attempt(2),
    )
    def _get(self, url, **kwargs):
        self._init_access_token()
        return self.session.get(url, **kwargs)

    def create_plugin_report(self, sha256, file_path=None):
        """Request a block-level report for sha256.

        If 404, auto-submits the file for analysis then retries.
        Returns the result_url string for polling.
        """
        response = self._post(URLS['create_plugin_report'].format(sha256))

        if response.status_code == 403:
            raise InsufficientQuotaException(
                'Daily quota reached. Contact support@intezer.com.'
            )

        if response.status_code == 404:
            self._submit_for_analysis(sha256, file_path)
            response = self._post(URLS['create_plugin_report'].format(sha256))

        if response.status_code == 409:
            raise UnsupportedFileException('File type not supported for Intezer plugin report.')

        if response.status_code != 201:
            response.raise_for_status()

        return response.json()['result_url']

    def _submit_for_analysis(self, sha256, file_path=None):
        try:
            if file_path and os.path.isfile(file_path):
                with open(file_path, 'rb') as fh:
                    response = self._post(
                        URLS['analyze_file'],
                        files={'file': (os.path.basename(file_path), fh)},
                    )
            else:
                response = self._post(URLS['analyze_hash'], json={'hash': sha256})

            result_url = response.json()['result_url']
            self.poll_result(result_url, with_api_version=True)
        except Exception:
            raise FileNotAnalyzedException(
                'File not found in Intezer. Analyze it first at {}'.format(BASE_URL)
            )

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(tenacity.TryAgain),
        stop=tenacity.stop_after_delay(600),
        wait=tenacity.wait_fixed(5),
    )
    def poll_result(self, result_url, with_api_version=False):
        """Poll until job completes. Returns the result dict."""
        base = '{}/{}/'.format(API_URL, API_VERSION) if with_api_version else API_URL
        response = self._get(base + result_url)

        if response.status_code == 202:
            raise tenacity.TryAgain()

        response.raise_for_status()
        return response.json()['result']

    def get_analysis_url(self, result_url):
        analysis_id = result_url.split('/')[3]
        return '{}/{}?utm_campaign=binja_plugin'.format(ANALYSES_URL, analysis_id)
