#!/usr/bin/env python

import hashlib
import io
import json
import multiprocessing
import os
import sys
from collections import OrderedDict
from logging import INFO
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
        headers = {'Authorization': 'Token lalala'}
        session = wc.make_session(auth, headers)
        assert session.auth == auth
        assert 'Authorization' in session.headers

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

        # Drain the JoinableQueue to avoid BrokenPipeError.
        # There could be a better way to handle this...
        for _ in (1, 2):
            q_item = j_queue.get()
            assert isinstance(q_item, wc.DataFile)
            j_queue.task_done()
        # Verify it was two items on the queue.
        assert j_queue.empty()

    def test_populate_downloads_multi_page(self, mock_session):
        """Test the queue returned for multiple results pages."""
        # Give the first of our two page responses a next page URL.
        p1 = WASAPI_TEXT.replace('"next":null', '"next":"http://test?page=2"')
        responses = [MockResponse200(p1), MockResponse200()]
        mock_session.return_value.get.side_effect = responses
        downloads = wc.Downloads(WASAPI_URL, download=True)
        j_queue = downloads.get_q

        # Drain the JoinableQueue to avoid BrokenPipeError.
        for _ in range(4):
            q_item = j_queue.get()
            assert isinstance(q_item, wc.DataFile)
            j_queue.task_done()
        # Verify there were only 4 items on the queue.
        assert j_queue.empty()

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
            'edef6bca652d75d0587ef411d5f028335341b074  {p}{s}AIT-JOB256123-00000.warc.gz\n'
            '54a466421471ef7d8cb4d6bbfb85afd76022a378  {p}{s}ARCHIVEIT-JOB256118-00000.warc.gz\n'
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
    locations = ['http://loc1/blah.warc.gz', 'http://loc2/blah.warc.gz']
    filename = 'blah.warc.gz'
    checksums = {'sha1': '33304d104f95d826da40079bad2400dc4d005403',
                 'md5': '62f87a969af0dd857ecd6c3e7fde6aed'}
    size = 12345678
    data_file = wc.DataFile(locations, filename, checksums, size)

    def test_download_file_200(self):
        session = requests.Session()
        mock_200 = MockResponse200('')

        with patch.object(session, 'get', return_value=mock_200) as mock_get, \
                patch('wasapi_client.write_file') as mock_write_file:
            file_data = wc.download_file(self.data_file, session, self.filename)

        # Check we only tried downloading files until successful download.
        mock_get.assert_called_once_with(self.locations[0], stream=True)
        mock_write_file.assert_called_once_with(mock_200, self.filename)
        assert not file_data.verified

    def test_download_file_not_200(self):
        session = requests.Session()
        mock_403 = MockResponse403()

        with patch.object(session, 'get', return_value=mock_403) as mock_get, \
                pytest.raises(wc.WASAPIDownloadError) as err:
            wc.download_file(self.data_file, session, self.filename)
        for item in (str(self.locations), self.filename):
            assert item in err.value.args[0]
        # Check all locations were tried.
        calls = [call(self.locations[0], stream=True),
                 call(self.locations[1], stream=True)]
        mock_get.assert_has_calls(calls)

    def test_download_get_raises_some_RequestException(self, caplog):
        caplog.set_level(INFO)
        session = requests.Session()
        mock_200 = MockResponse200('')

        with patch.object(session, 'get') as mock_get, \
                patch('wasapi_client.write_file') as mock_write_file:
            # Raise a subclass of RequestException on first download attempt;
            # mock a successful response on the second attempt
            mock_get.side_effect = [requests.exceptions.ConnectionError(),
                                    mock_200]
            wc.download_file(self.data_file, session, self.filename)

        # Check all locations were tried.
        calls = [call(self.locations[0], stream=True),
                 call(self.locations[1], stream=True)]
        mock_get.assert_has_calls(calls)
        mock_write_file.assert_called_once_with(mock_200, self.filename)
        # Verify requests exception was caught and logged.
        for msg in ('Error downloading http://loc1/blah.warc.gz:',
                    'http://loc2/blah.warc.gz: 200 OK'):
            assert msg in caplog.text

    def test_download_file_OSError(self):
        session = requests.Session()
        mock_200 = MockResponse200('')

        with patch.object(session, 'get', return_value=mock_200) as mock_get, \
                patch('wasapi_client.write_file') as mock_write_file:
            mock_write_file.side_effect = OSError
            with pytest.raises(wc.WASAPIDownloadError) as err:
                wc.download_file(self.data_file, session, self.filename)

        for item in (str(self.locations), self.filename):
            assert item in err.value.args[0]
        # Check we only tried downloading files until successful download.
        mock_get.assert_called_once_with(self.locations[0], stream=True)
        mock_write_file.assert_called_once_with(mock_200, self.filename)

    def test_download_check_exists_true(self):
        """Test a file already existing on the filesystem is not downloaded."""
        with patch('wasapi_client.check_exists', return_value=True), \
                patch('requests.Session', autospec=True) as mock_session:
            file_data = wc.download_file(self.data_file, mock_session, self.filename)
        # Check `verified` has been set True on the FileData instance.
        assert file_data.verified
        # Check that no get request was made.
        assert not mock_session.get.called

    def test_download_uses_pre_signed_url(self):
        """Test that an s3 URL uses requests.get, not a session."""
        locations = ['https://data.s3.amazonaws.com/warcs/blah.warc.gz?Signature=xyz',
                     'http://loc2/blah.warc.gz']
        filename = 'blah.warc.gz'
        checksums = {'md5': '72b484a2610cb54ec22e48c8104ba3bd'}
        data_file = wc.DataFile(locations, filename, checksums, 123456)
        mock_200 = MockResponse200('')

        with patch('requests.get', return_value=mock_200) as mock_get, \
                patch('wasapi_client.write_file') as mock_write_file:
            wc.download_file(data_file, requests.Session(), filename)

        # Check we attempted one download via requests.get and wrote the file.
        mock_get.assert_called_once_with(locations[0], stream=True)
        mock_write_file.assert_called_once_with(mock_200, filename)


class Test_check_exists:
    def test_check_exists_return_true(self):
        checksums = {'sha1': '33304d104f95d826da40079bad2400dc4d005403'}
        with patch('os.path.isfile', return_value=True), \
                patch('os.path.getsize', return_value=123456), \
                patch('wasapi_client.verify_file', return_value=True) as mock_verify:
            assert wc.check_exists('path', 123456, checksums)
            mock_verify.assert_called_once_with(checksums, 'path')

    @patch('os.path.isfile', return_value=False)
    @patch('os.path.getsize')
    def test_check_exists_no_file(self, mock_getsize, mock_isfile):
        assert not wc.check_exists('path', 123456, {})
        mock_isfile.assert_called_once_with('path')
        assert not mock_getsize.called

    @patch('os.path.isfile', return_value=True)
    @patch('os.path.getsize', return_value=123456)
    @patch('wasapi_client.verify_file')
    def test_check_exists_file_size_mismatch(self, mock_verify, mock_getsize, mock_isfile):
        assert not wc.check_exists('path', 789, {})
        mock_isfile.assert_called_once_with('path')
        mock_getsize.assert_called_once_with('path')
        assert not mock_verify.called

    def test_check_exists_checksum_fail(self):
        with patch('os.path.isfile', return_value=True), \
                patch('os.path.getsize', return_value=123456), \
                patch('wasapi_client.verify_file', return_value=False) as mock_verify:
            assert not wc.check_exists('path', 123456, {})
            mock_verify.assert_called_once_with({}, 'path')


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
        algorithm = 'sha1'
        path = 'dummy/path'
        checksums = {algorithm: checksum}
        mock_calc_sum.return_value = checksum + 'notmatching'
        with patch('wasapi_client.LOGGER', autospec=True) as mock_logger:
            assert not wc.verify_file(checksums, path)
        msg = 'Checksum {} mismatch for {}: expected {}, got {}notmatching'.format(algorithm,
                                                                                   path,
                                                                                   checksum,
                                                                                   checksum)
        mock_logger.error.assert_called_once_with(msg)

    @patch('wasapi_client.calculate_sum')
    def test_verify_file_one_supported_algorithm(self, mock_calc_sum):
        """Test one unsupported/one supported algorithm returns True."""
        checksum = '33304d104f95d826da40079bad2400dc4d005403'
        checksums = OrderedDict([('abc', 'algorithm_unsupported'),
                                 ('sha1', checksum)])
        mock_calc_sum.return_value = checksum
        with patch('wasapi_client.LOGGER', autospec=True) as mock_logger:
            assert wc.verify_file(checksums, 'dummy/path')
        # Check that unsupported algorithm was tried.
        mock_logger.debug.assert_called_once_with('abc is unsupported')
        mock_logger.info.assert_called_once_with('Checksum success at: dummy/path')

    @patch('wasapi_client.calculate_sum')
    def test_verify_file_s3etag_algorithm_regular_md5(self, mock_calc_sum):
        checksum = '72b484a2610cb54ec22e48c8104ba3bd'
        checksums = {'s3etag': checksum}
        mock_calc_sum.return_value = checksum
        assert wc.verify_file(checksums, 'dummy/path')
        # Verify the hash_function used was md5.
        mock_calc_sum.assert_called_once_with(hashlib.md5, 'dummy/path', wc.READ_LIMIT)

    @patch('wasapi_client.calculate_sum')
    def test_verify_file_s3etag_algorithm_double_md5(self, mock_calc_sum):
        checksum = 'ceb8853ddc5086cc4ab9e149f8f09c88-2'
        checksums = {'s3etag': checksum}
        mock_calc_sum.return_value = checksum
        assert wc.verify_file(checksums, 'dummy/path')
        # Verify s3etag value containing a '-' uses S3DoubleMD5 and custom read_limit.
        mock_calc_sum.assert_called_once_with(wc.S3DoubleMD5, 'dummy/path', 1024*1024*8)


class Test_S3DoubleMD5:
    def test_S3DoubleMD5_single_md5(self):
        content = b'We are updating this once.'
        s3md5 = wc.S3DoubleMD5()
        s3md5.update(content)
        # Calling update once means length of s3md5.md5s is 1, and
        # hexdigest is same as for regular md5.
        assert len(s3md5.md5s) == 1
        assert s3md5.hexdigest() == hashlib.md5(content).hexdigest()

    def test_S3DoubleMD5_double_md5(self):
        content = b'We are updating this once.\nTwice.\nAnd three times.'
        s3md5 = wc.S3DoubleMD5()
        # Cause update to be called three times.
        for line in content.split(b'\n'):
            s3md5.update(line)
        # S3DoubleMD5 hexdigest should be the hexdigest of the concatenation
        # of the digests of the 3 items in s3md5.md5s and a '-3'
        # for the number of digests that were concatenated.
        assert len(s3md5.md5s) == 3
        assert s3md5.hexdigest() == '8e73850eb35bebe8ebd2896dd9032e48-3'


class Test_calculate_sum:
    @pytest.mark.skipif(sys.version_info < (3, 4, 4), reason=('bug via mock_open '
                        'https://github.com/python/cpython/commit/86b34d'))
    def test_calculate_sum(self):
        data = 'data from file'.encode('utf-8')
        with patch('builtins.open', mock_open(read_data=data)):
            checksum = wc.calculate_sum(hashlib.sha1, 'dummy/path')
        assert checksum == hashlib.sha1(data).hexdigest()


class Test_convert_queue:
    def test_convert_queue(self):
        m = multiprocessing.Manager()
        q = m.Queue()
        q.put(('success', 'name1'))
        q.put(('failure', 'name2'))
        dict_from_q = wc.convert_queue(q)
        assert dict_from_q['success'] == ['name1']
        assert dict_from_q['failure'] == ['name2']
        m.shutdown()


class Test_generate_report:
    def test_generate_report_all_success(self):
        m = multiprocessing.Manager()
        q = m.Queue()
        q.put(('success', 'name1'))
        q.put(('success', 'name2'))
        report = wc.generate_report(q)
        assert report == ('Total downloads attempted: 2\n'
                          'Successful downloads: 2\n'
                          'Failed downloads: 0\n')
        m.shutdown()

    def test_generate_report_one_failure(self):
        m = multiprocessing.Manager()
        q = m.Queue()
        q.put(('success', 'name1'))
        q.put(('failure', 'name2'))
        report = wc.generate_report(q)
        assert report == ('Total downloads attempted: 2\n'
                          'Successful downloads: 1\n'
                          'Failed downloads: 1\n'
                          'Failed files (see log for details):\n'
                          '    name2\n')
        m.shutdown()

    def test_generate_report_all_failure(self):
        m = multiprocessing.Manager()
        q = m.Queue()
        q.put(('failure', 'name1'))
        q.put(('failure', 'name2'))
        report = wc.generate_report(q)
        assert report == ('Total downloads attempted: 2\n'
                          'Successful downloads: 0\n'
                          'Failed downloads: 2\n')
        m.shutdown()


class TestDownloader:
    locations = ['http://loc1/blah.warc.gz', 'http://loc2/blah.warc.gz']
    filename = 'blah.warc.gz'
    checksums = {'sha1': '33304d104f95d826da40079bad2400dc4d005403',
                 'md5': '62f87a969af0dd857ecd6c3e7fde6aed'}
    size = 12345678
    data_file = wc.DataFile(locations, filename, checksums, size)

    def test_run(self):
        """Test downloader when downloads are successful."""
        # Create a queue holding two sets of file data.
        get_q = multiprocessing.JoinableQueue()
        for _ in (1, 2):
            get_q.put(self.data_file)
        manager = multiprocessing.Manager()
        result_q = manager.Queue()
        log_q = manager.Queue()
        with patch('wasapi_client.verify_file', return_value=True), \
                patch('wasapi_client.download_file', return_value=self.data_file):
            p = wc.Downloader(get_q, result_q, log_q)
            p.start()
            p.run()
        # If the join doesn't block, the queue is fully processed.
        get_q.join()
        # Verify there is nothing on the log_q.
        assert log_q.empty()
        for _ in (1, 2):
            assert result_q.get() == ('success', self.filename)
        # Verify those were the only two results on the result_q.
        assert result_q.empty()

    @patch('wasapi_client.download_file')
    def test_run_WASAPIDownloadError(self, mock_download):
        """Test downloader when downloads fail."""
        expected_error = 'WD Error'
        mock_download.side_effect = wc.WASAPIDownloadError(expected_error)
        # Create a queue holding two sets of file data.
        get_q = multiprocessing.JoinableQueue()
        for _ in (1, 2):
            get_q.put(self.data_file)
        manager = multiprocessing.Manager()
        result_q = manager.Queue()
        log_q = manager.Queue()
        p = wc.Downloader(get_q, result_q, log_q)
        p.start()
        p.run()
        # If the join doesn't block, the queue is fully processed.
        get_q.join()
        for _ in (1, 2):
            assert log_q.get().msg == expected_error
            assert result_q.get() == ('failure', self.filename)
        # Verify those were the only two results on the result_q.
        # Sometimes `empty` needs a moment to register.
        assert result_q.empty()

    def test_run_file_already_verified(self):
        """Test a downloaded file is not verified twice."""
        return_data_file = wc.DataFile(self.locations, self.filename, self.checksums, self.size)
        return_data_file.verified = True
        # Create a queue holding two sets of file data.
        get_q = multiprocessing.JoinableQueue()
        for _ in (1, 2):
            get_q.put(self.data_file)
        manager = multiprocessing.Manager()
        result_q = manager.Queue()
        log_q = manager.Queue()
        with patch('wasapi_client.verify_file', return_value=True) as mock_verify, \
                patch('wasapi_client.download_file', return_value=return_data_file):
            p = wc.Downloader(get_q, result_q, log_q)
            p.start()
            p.run()
        # If the join doesn't block, the queue is fully processed.
        get_q.join()
        assert log_q.empty()
        for _ in (1, 2):
            assert result_q.get() == ('success', self.filename)
        assert result_q.empty()
        # Check verify_exists was not called, since it was called in `download_file`.
        assert not mock_verify.called


class Test_parse_args:
    @patch('wasapi_client.multiprocessing.cpu_count')
    def test_default_processes(self, mock_cpu_count):
        """Test handling of cpu_count() erroring.

        Could happen when cpu_count isn't implemented on a platform
        and --processes isn't specified by the user.
        """
        mock_cpu_count.side_effect = NotImplementedError
        args = wc._parse_args(['--crawl', '12'])
        assert args.processes == 1

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


class Test_get_credentials_env:
    def test_get_credentials_env(self):
        """Test auth credentials are set from environment variables."""
        with patch.dict('os.environ', {'WASAPI_USER': 'me', 'WASAPI_PASS': 'p@ss123'}):
            auth = wc.get_credentials_env()
        assert auth == ('me', 'p@ss123')

    def test_get_credentials_env_missing_one_env_var(self):
        """Test a None value for username or password causes no auth."""
        with patch('os.environ.get') as mock_get:
            mock_get.side_effect = ['me', None]
            auth = wc.get_credentials_env()
        assert auth is None


class Test_get_credentials_config:
    def test_get_credentials_config(self):
        """Test auth can be populated from a config file."""
        stream = io.StringIO('[unt]\nusername = me\npassword = p@ss123')
        with patch('builtins.open', return_value=stream):
            auth = wc.get_credentials_config('unt')
        assert auth == ('me', 'p@ss123')

    def test_get_credentials_config_missing_profile(self):
        """Test program exits if the profile supplied doesn't exist."""
        stream = io.StringIO('[unt]\nusername = me\npassword = p@ss123')
        with patch('builtins.open', return_value=stream), \
                pytest.raises(SystemExit):
            wc.get_credentials_config('home')

    def test_get_credentials_config_missing_password(self):
        """Test program exits if config does not supply an expected option."""
        stream = io.StringIO('[unt]\nusername = me')
        with patch('builtins.open', return_value=stream), \
                pytest.raises(SystemExit):
            wc.get_credentials_config('unt')


class Test_get_credentials:
    @patch('getpass.getpass', return_value='p@ss123')
    def test_get_credentials_from_getpass(self, mock_getpass):
        auth = wc.get_credentials(user='me')
        assert auth == ('me', 'p@ss123')
        mock_getpass.assert_called_once_with()

    @patch('wasapi_client.get_credentials_env', return_value=('me', 'p@ss123'))
    def test_get_credentials_from_env(self, mock_gce):
        auth = wc.get_credentials()
        assert auth == ('me', 'p@ss123')
        mock_gce.assert_called_once_with()

    @patch('wasapi_client.get_credentials_env', return_value=None)
    @patch('wasapi_client.get_credentials_config', return_value=('me', 'p@ss123'))
    def test_get_credentials_from_config(self, mock_gcc, mock_gce):
        auth = wc.get_credentials(profile='unt')
        assert auth == ('me', 'p@ss123')
        mock_gcc.assert_called_once_with('unt')
        mock_gce.assert_called_once_with()

    @patch('wasapi_client.get_credentials_env', return_value=None)
    @patch('wasapi_client.get_credentials_config')
    def test_get_credentials_no_credentials_provided(self, mock_gcc, mock_gce):
        """Test if no user/profile is provided and no valid config file exists."""
        auth = wc.get_credentials()
        assert auth is None
        assert not mock_gcc.called
        mock_gce.assert_called_once_with()
