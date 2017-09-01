#!/usr/bin/env python

import hashlib
import json
import multiprocessing
import os
from collections import OrderedDict
from unittest.mock import call, mock_open, patch

import pytest
import requests

import wasapi_client as wc


WASAPI_URL = 'http://example.com/webdata'

WASAPI_TEXT = "".join("""{
  "count": 2,
  "files": [
    {
      "account": 1,
      "checksums": {
        "md5": "61f818912d1f39bc9dd15d4b87461110",
        "sha1": "edef6bca652d75d0587ef411d5f028335341b074"
      },
      "collection": 7967,
      "crawl": 256123,
      "crawl-start": "2016-12-22T14:07:24Z",
      "crawl-time": "2016-12-22T18:55:12Z",
      "filename": "AIT-JOB256123-00000.warc.gz",
      "filetype": "warc",
      "locations": [
        "https://warcs.example.com/webdatafile/AIT-JOB256123-00000.warc.gz",
        "https://example.com/download/AIT-JOB256123-00000.warc.gz"
      ],
      "size": 943100093
    },
    {
      "account": 1,
      "checksums": {
        "md5": "748120fd9672b22df5942bb44e9cde81",
        "sha1": "54a466421471ef7d8cb4d6bbfb85afd76022a378"
      },
      "collection": 7967,
      "crawl": 256118,
      "crawl-start": "2016-12-22T14:01:53Z",
      "crawl-time": "2016-12-22T14:01:58Z",
      "filename": "ARCHIVEIT-JOB256118-00000.warc.gz",
      "filetype": "warc",
      "locations": [
        "https://warcs.example.com/webdatafile/AIT-JOB256118-00000.warc.gz",
        "https://example.com/download/AIT-JOB256118-00000.warc.gz"
      ],
      "size": 6265488
    }
  ],
  "includes-extra": false,
  "next": null,
  "previous": null,
  "request-url": "https://example.com/wasapi/v1/webdata"
}""".split())


NO_FILES = """{
  "count": 0,
  "files": [],
  "request-url": "https://example.com/wasapi/v1/webdata",
  "includes-extra": false,
  "next": null,
  "previous": null
}"""


class MockResponse200:
    """A mocked successful requests GET response from WASAPI."""

    def __init__(self, text=WASAPI_TEXT):
        self.status_code = 200
        self.text = text
        self.reason = 'OK'

    def json(self):
        return json.loads(self.text)


class MockResponse403:
    """A mocked unsuccessful requests GET response from WASAPI."""

    def __init__(self):
        self.status_code = 403
        self.reason = 'Forbidden'


class Test_make_session:
    def test_make_session_auth(self):
        auth = ('user', 'pass')
        session = wc.make_session(auth)
        assert session.auth == auth

    def test_make_session_no_auth(self):
        session = wc.make_session(None)
        assert session.auth is None


class Test_get_webdata:
    def test_get_webdata(self):
        """Test a successful response."""
        session = requests.Session()
        with patch.object(session, 'get', return_value=MockResponse200()):
            response = wc.get_webdata(WASAPI_URL, session)
        # Compare with whitespace stripped.
        response_text = "".join(json.dumps(response, sort_keys=True).split())
        assert response_text == WASAPI_TEXT

    def test_get_webdata_403_forbidden(self):
        """Test bad authentication handling."""
        session = requests.Session()
        with patch.object(session, 'get', return_value=MockResponse403()):
            with pytest.raises(SystemExit):
                wc.get_webdata(WASAPI_URL, session)

    def test_get_webdata_ConnectionError(self):
        """Test host connection isn't made."""
        session = requests.Session()
        error = requests.exceptions.ConnectionError
        with patch.object(session, 'get', side_effect=error):
            with pytest.raises(SystemExit):
                wc.get_webdata(WASAPI_URL, session)

    def test_get_webdata_json_error(self):
        """Test 200 non-JSON repsonse exits."""
        session = requests.Session()
        text = 'response text is not json'
        with patch.object(session, 'get', return_value=MockResponse200(text)):
            with pytest.raises(SystemExit):
                wc.get_webdata(WASAPI_URL, session)


@patch('requests.Session')
class Test_Downloads:
    def test_populate_downloads(self, mock_session):
        """Test a queue is returned with expected data."""
        mock_session.return_value.get.return_value = MockResponse200()
        downloads = wc.Downloads(WASAPI_URL, download=True)
        j_queue = downloads.get_q
        assert j_queue.qsize() == 2
        # Drain the JoinableQueue to avoid BrokenPipeError.
        # There could be a better way to handle this...
        while j_queue.qsize():
            q_item = j_queue.get()
            j_queue.task_done()
        for field in ['locations', 'filename', 'checksums']:
            assert field in q_item

    def test_populate_downloads_multi_page(self, mock_session):
        """Test the queue returned for multiple results pages."""
        # Give the first of our two page responses a next page URL.
        p1 = WASAPI_TEXT.replace('"next":null', '"next":"http://test?page=2"')
        responses = [MockResponse200(p1), MockResponse200()]
        mock_session.return_value.get.side_effect = responses
        downloads = wc.Downloads(WASAPI_URL, download=True)
        j_queue = downloads.get_q
        assert j_queue.qsize() == 4
        # Drain the JoinableQueue to avoid BrokenPipeError.
        while j_queue.qsize():
            q_item = j_queue.get()
            j_queue.task_done()
        for field in ('locations', 'filename', 'checksums'):
            assert field in q_item

    def test_populate_downloads_no_get_q(self, mock_session):
        """Test download=False prevents get_q attribute existing."""
        mock_session.return_value.get.return_value = MockResponse200()
        downloads = wc.Downloads(WASAPI_URL, download=False)
        with pytest.raises(AttributeError):
            getattr(downloads, 'get_q')

    def test_populate_downloads_urls(self, mock_session):
        """Test urls is populated with first location per file."""
        mock_session.return_value.get.return_value = MockResponse200()
        downloads = wc.Downloads(WASAPI_URL, download=False)
        assert len(downloads.urls) == 2
        for url in ['https://warcs.example.com/webdatafile/AIT-JOB256123-00000.warc.gz',
                    'https://warcs.example.com/webdatafile/AIT-JOB256118-00000.warc.gz']:
            assert url in downloads.urls

    def test_populate_downloads_manifest(self, mock_session):
        """Test the checksums dict is populated."""
        mock_session.return_value.get.return_value = MockResponse200()
        downloads = wc.Downloads(WASAPI_URL, download=False)
        assert len(downloads.checksums)
        assert downloads.checksums['md5'] == [('61f818912d1f39bc9dd15d4b87461110',
                                               'AIT-JOB256123-00000.warc.gz'),
                                              ('748120fd9672b22df5942bb44e9cde81',
                                               'ARCHIVEIT-JOB256118-00000.warc.gz')]
        assert downloads.checksums['sha1'] == [('edef6bca652d75d0587ef411d5f028335341b074',
                                                'AIT-JOB256123-00000.warc.gz'),
                                               ('54a466421471ef7d8cb4d6bbfb85afd76022a378',
                                                'ARCHIVEIT-JOB256118-00000.warc.gz')]

    def test_populate_downloads_manifest_destination(self, mock_session):
        """Test the checksums dict is populated with destination included."""
        mock_session.return_value.get.return_value = MockResponse200()
        downloads = wc.Downloads(WASAPI_URL, download=False, destination='{}tmp'.format(os.sep))
        assert len(downloads.checksums)
        assert downloads.checksums['md5'] == [
            ('61f818912d1f39bc9dd15d4b87461110',
             os.path.normpath('/tmp/AIT-JOB256123-00000.warc.gz')),
            ('748120fd9672b22df5942bb44e9cde81',
             os.path.normpath('/tmp/ARCHIVEIT-JOB256118-00000.warc.gz'))
        ]
        assert downloads.checksums['sha1'] == [
            ('edef6bca652d75d0587ef411d5f028335341b074',
             os.path.normpath('/tmp/AIT-JOB256123-00000.warc.gz')),
            ('54a466421471ef7d8cb4d6bbfb85afd76022a378',
             os.path.normpath('/tmp/ARCHIVEIT-JOB256118-00000.warc.gz'))
        ]

    def test_populate_downloads_generate_manifest(self, mock_session, tmpdir):
        """Test checksum files are created for all algorithms."""
        mock_session.return_value.get.return_value = MockResponse200()
        sub_dir = 'downloads'
        dest = tmpdir.mkdir(sub_dir)
        downloads = wc.Downloads(WASAPI_URL, download=False, destination=str(dest))
        downloads.generate_manifests()
        sub_dir_contents = dest.listdir()
        assert len(sub_dir_contents) == 2
        for name in ['manifest-md5.txt', 'manifest-sha1.txt']:
            assert dest.join(name) in sub_dir_contents

    def test_write_manifest_file(self, mock_session, tmpdir):
        """Test a manifest file is written for the given algorithm."""
        mock_session.return_value.get.return_value = MockResponse200()
        sub_dir = 'downloads'
        dest = tmpdir.mkdir(sub_dir)
        downloads = wc.Downloads(WASAPI_URL, download=False, destination=str(dest))
        downloads.write_manifest_file('sha1')
        assert len(dest.listdir()) == 1
        txt = (
            'edef6bca652d75d0587ef411d5f028335341b074\t{p}{s}AIT-JOB256123-00000.warc.gz\n'
            '54a466421471ef7d8cb4d6bbfb85afd76022a378\t{p}{s}ARCHIVEIT-JOB256118-00000.warc.gz\n'
        )
        assert dest.join('manifest-sha1.txt').read() == txt.format(p=dest, s=os.sep)

    def test_write_manifest_file_wrong_algorithm(self, mock_session, tmpdir):
        """Test writing a manifest file for an algorithm we don't have."""
        mock_session.return_value.get.return_value = MockResponse200()
        sub_dir = 'downloads'
        dest = tmpdir.mkdir(sub_dir)
        downloads = wc.Downloads(WASAPI_URL, download=False, destination=str(dest))
        with pytest.raises(wc.WASAPIManifestError):
            downloads.write_manifest_file('sha2')


@patch('requests.Session')
class Test_get_files_count:
    def test_get_files_count(self, mock_session):
        mock_session.return_value.get.return_value = MockResponse200()
        count = wc.get_files_count(WASAPI_URL)
        assert count == 2


@patch('requests.Session')
class Test_get_files_size:
    def test_get_files_size(self, mock_session):
        mock_session.return_value.get.return_value = MockResponse200()
        count, total = wc.get_files_size(WASAPI_URL)
        assert count == 2
        assert total == 949365581

    def test_get_files_size_multi_page(self, mock_session):
        # Give the first of our two page responses a next page URL.
        p1 = WASAPI_TEXT.replace('"next":null',
                                 '"next":"{}?page=2"'.format(WASAPI_URL))
        # The value for `count` is pulled from the last page. Though,
        # in actuality, `count` should be same on all pages.
        p2 = WASAPI_TEXT.replace('"count":2', '"count":4')
        responses = [MockResponse200(p1), MockResponse200(p2)]
        mock_session.return_value.get.side_effect = responses
        count, total = wc.get_files_size(WASAPI_URL)
        assert count == 4
        assert total == 949365581 * 2

    def test_get_files_size_no_files(self, mock_session):
        mock_session.return_value.get.return_value = MockResponse200(NO_FILES)
        count, total = wc.get_files_size(WASAPI_URL)
        assert count == 0
        assert total == 0


class Test_convert_bytes:
    @pytest.mark.parametrize('size, expected', [
        (0, '0.0B'),
        (1023, '1023.0B'),
        (1024, '1.0KB'),
        (1024000, '1000.0KB'),
        (1048576, '1.0MB'),
        (1073741824, '1.0GB'),
        (1099511628000, '1.0TB')
    ])
    def test_convert_bytes(self, size, expected):
        assert wc.convert_bytes(size) == expected


class Test_download_file:
    FILE_DATA = {
        'locations': ['http://loc1/blah.warc.gz',
                      'http://loc2/blah.warc.gz'],
        'filename': 'blah.warc.gz',
        'checksums': {'sha1': '33304d104f95d826da40079bad2400dc4d005403',
                      'md5': '62f87a969af0dd857ecd6c3e7fde6aed'}
    }

    def test_download_file_200(self):
        session = requests.Session()
        mock_200 = MockResponse200('')
        loc = self.FILE_DATA['locations'][0]
        filename = self.FILE_DATA['filename']

        with patch.object(session, 'get', return_value=mock_200) as mock_get, \
                patch('wasapi_client.write_file') as mock_write_file:
            wc.download_file(self.FILE_DATA, session, filename)

        # Check we only tried downloading files until successful download.
        mock_get.assert_called_once_with(loc, stream=True)
        mock_write_file.assert_called_once_with(mock_200, filename)

    def test_download_file_not_200(self):
        session = requests.Session()
        mock_403 = MockResponse403()
        locations = self.FILE_DATA['locations']
        filename = self.FILE_DATA['filename']

        with patch.object(session, 'get', return_value=mock_403) as mock_get, \
                pytest.raises(wc.WASAPIDownloadError) as err:
            wc.download_file(self.FILE_DATA, session, filename)

        for item in (str(locations), filename):
            assert item in str(err)
        # Check all locations were tried.
        calls = [call(locations[0], stream=True),
                 call(locations[1], stream=True)]
        mock_get.assert_has_calls(calls)

    def test_download_file_OSError(self):
        session = requests.Session()
        mock_200 = MockResponse200('')
        locations = self.FILE_DATA['locations']
        filename = self.FILE_DATA['filename']

        with patch.object(session, 'get', return_value=mock_200) as mock_get, \
                patch('wasapi_client.write_file') as mock_write_file:
            mock_write_file.side_effect = OSError
            with pytest.raises(wc.WASAPIDownloadError) as err:
                wc.download_file(self.FILE_DATA, session, filename)

        for item in (str(locations), filename):
            assert item in str(err)
        # Check we only tried downloading files until successful download.
        mock_get.assert_called_once_with(locations[0], stream=True)
        mock_write_file.assert_called_once_with(mock_200, filename)


class Test_verify_file:
    @patch('wasapi_client.calculate_sum')
    def test_verify_file(self, mock_calc_sum):
        """Test a matching checksum returns True."""
        checksum = '33304d104f95d826da40079bad2400dc4d005403'
        checksums = {'sha1': checksum}
        mock_calc_sum.return_value = checksum
        assert wc.verify_file(checksums, 'dummy/path')

    def test_verify_file_unsupported_algorithm(self):
        """Test all algorithms being unsupported returns False."""
        checksums = {'shaq1': 'shaq1algorithmdoesnotexist'}
        assert not wc.verify_file(checksums, 'dummy/path')

    @patch('wasapi_client.calculate_sum')
    def test_verify_file_checksum_mismatch(self, mock_calc_sum):
        """Test calculated checksum does not match the expected."""
        checksum = '33304d104f95d826da40079bad2400dc4d005403'
        checksums = {'sha1': checksum}
        mock_calc_sum.return_value = checksum + 'notmatching'
        with patch('wasapi_client.logging', autospec=True) as mock_logging:
            assert not wc.verify_file(checksums, 'dummy/path')
        msg = 'Checksum mismatch for dummy/path: expected {}, got {}notmatching'.format(checksum,
                                                                                        checksum)
        mock_logging.error.assert_called_once_with(msg)

    @patch('wasapi_client.calculate_sum')
    def test_verify_file_one_supported_algorithm(self, mock_calc_sum):
        """Test one unsupported/one supported algorithm returns True."""
        checksum = '33304d104f95d826da40079bad2400dc4d005403'
        checksums = OrderedDict([('abc', 'algorithm_unsupported'),
                                 ('sha1', checksum)])
        mock_calc_sum.return_value = checksum
        with patch('wasapi_client.logging', autospec=True) as mock_logging:
            assert wc.verify_file(checksums, 'dummy/path')
        # Check that unsupported algorithm was tried.
        mock_logging.debug.assert_called_once_with('abc is unsupported')
        mock_logging.info.assert_called_once_with('Checksum success at: dummy/path')


class Test_calculate_sum:
    def test_calculate_sum(self):
        data = b'data from file'
        with patch('wasapi_client.open', mock_open(read_data=data)):
            checksum = wc.calculate_sum(hashlib.sha1, 'dummy/path')
        assert checksum == hashlib.sha1(data).hexdigest()


class Test_convert_queue:
    def test_convert_queue(self):
        q = multiprocessing.Manager().Queue()
        q.put(('success', 'name1'))
        q.put(('failure', 'name2'))
        dict_from_q = wc.convert_queue(q)
        assert dict_from_q['success'] == ['name1']
        assert dict_from_q['failure'] == ['name2']


class Test_generate_report:
    def test_generate_report_all_success(self):
        q = multiprocessing.Manager().Queue()
        q.put(('success', 'name1'))
        q.put(('success', 'name2'))
        report = wc.generate_report(q)
        assert report == ('Total downloads attempted: 2\n'
                          'Successful downloads: 2\n'
                          'Failed downloads: 0\n')

    def test_generate_report_one_failure(self):
        q = multiprocessing.Manager().Queue()
        q.put(('success', 'name1'))
        q.put(('failure', 'name2'))
        report = wc.generate_report(q)
        assert report == ('Total downloads attempted: 2\n'
                          'Successful downloads: 1\n'
                          'Failed downloads: 1\n'
                          'Failed files (see log for details):\n'
                          '    name2\n')

    def test_generate_report_all_failure(self):
        q = multiprocessing.Manager().Queue()
        q.put(('failure', 'name1'))
        q.put(('failure', 'name2'))
        report = wc.generate_report(q)
        assert report == ('Total downloads attempted: 2\n'
                          'Successful downloads: 0\n'
                          'Failed downloads: 2\n')


@patch('wasapi_client.download_file')
class TestDownloader:
    FILE_DATA = {
        'locations': ['http://loc1/blah.warc.gz',
                      'http://loc2/blah.warc.gz'],
        'filename': 'blah.warc.gz',
        'checksums': {'sha1': '33304d104f95d826da40079bad2400dc4d005403',
                      'md5': '62f87a969af0dd857ecd6c3e7fde6aed'}
    }

    def test_run(self, mock_download):
        """Test downloader when downloads are successful."""
        # Create a queue holding two sets of file data.
        get_q = multiprocessing.JoinableQueue()
        for _ in (1, 2):
            get_q.put(self.FILE_DATA)
        result_q = multiprocessing.Queue()
        log_q = multiprocessing.Queue()
        with patch('wasapi_client.verify_file', return_value=True):
            wc.Downloader(get_q, result_q, log_q).start()
        # If the join doesn't block, the queue is fully processed.
        get_q.join()
        assert result_q.qsize() == 2
        assert log_q.qsize() == 0
        for _ in (1, 2):
            assert result_q.get() == ('success', self.FILE_DATA['filename'])

    def test_run_WASAPIDownloadError(self, mock_download):
        """Test downloader when downloads fail."""
        mock_download.side_effect = wc.WASAPIDownloadError()
        # Create a queue holding two sets of file data.
        get_q = multiprocessing.JoinableQueue()
        for _ in (1, 2):
            get_q.put(self.FILE_DATA)
        result_q = multiprocessing.Queue()
        log_q = multiprocessing.Queue()
        wc.Downloader(get_q, result_q, log_q).start()
        # If the join doesn't block, the queue is fully processed.
        get_q.join()
        assert result_q.qsize() == 2
        assert log_q.qsize() == 2
        for _ in (1, 2):
            assert result_q.get() == ('failure', self.FILE_DATA['filename'])


class Test_parse_args:
    def test_SetQueryParametersAction(self):
        """Test that arguments passed with this action are in query_params."""
        args = wc._parse_args(['--crawl-start-after',
                               '2016-12-22T13:01:00',
                               '--crawl-start-before',
                               '2016-12-22T15:11:00',
                               '-c'])
        assert len(args.query_params) == 2
        assert args.query_params['crawl-start-after'] == '2016-12-22T13:01:00'
        assert args.query_params['crawl-start-before'] == '2016-12-22T15:11:00'

    def test_SetQueryParametersAction_multiple_collections(self):
        """Test multiple collections end up in query_params.

        A query can have multiple collections, so test that the
        user can supply multiple values.
        """
        args = wc._parse_args(['--collection', '12345', '98', '--crawl', '12'])
        assert len(args.query_params) == 2
        assert args.query_params['collection'] == ['12345', '98']
