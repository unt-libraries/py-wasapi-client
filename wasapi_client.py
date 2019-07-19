#!/usr/bin/env python

import argparse
import atexit
import configparser
import getpass
import hashlib
import logging
import logging.handlers
import math
import multiprocessing
import os
import requests
import sys
from collections import defaultdict
try:
    from json.decoder import JSONDecodeError
except ImportError:
    class JSONDecodeError(ValueError):
        pass
from queue import Empty
from urllib.parse import urlencode

NAME = 'wasapi_client' if __name__ == '__main__' else __name__

LOGGER = logging.getLogger(NAME)

READ_LIMIT = 1024 * 512

PROFILE_PATH = os.path.join(os.path.expanduser('~'), '.wasapi-client')


def start_listener_logging(log_q, path=''):
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    if path:
        handler = logging.FileHandler(filename=path)
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    # Get records from the queue and send them to the handler.
    listener = logging.handlers.QueueListener(log_q, handler)
    listener.start()

    return listener


def configure_main_logging(log_q, log_level=logging.ERROR):
    """Put a handler on the root logger.

    This allows handling log records from imported modules.
    """
    root = logging.getLogger()
    root.addHandler(logging.handlers.QueueHandler(log_q))
    root.setLevel(log_level)


def configure_worker_logging(log_q, log_level=logging.ERROR):
    """Configure logging for worker processes."""
    # Remove any existing handlers.
    LOGGER.handlers = []
    # Prevent root logger duplicating messages.
    LOGGER.propagate = False
    LOGGER.addHandler(logging.handlers.QueueHandler(log_q))
    LOGGER.setLevel(log_level)


class WASAPIDownloadError(Exception):
    pass


class WASAPIManifestError(Exception):
    pass


def make_session(auth=None, headers={}):
    """Make a session that will store our auth.

    `auth` is a tuple of the form (user, password)
    """
    session = requests.Session()
    session.auth = auth
    session.headers.update(headers)
    return session


def get_webdata(webdata_uri, session):
    """Make a request to the WASAPI."""
    try:
        response = session.get(webdata_uri)
    except requests.exceptions.ConnectionError as err:
        sys.exit('Could not connect at {}:\n{}'.format(webdata_uri, err))
    LOGGER.info('requesting {}'.format(webdata_uri))
    if response.status_code == 403:
        sys.exit('Verify user/password for {}:\n{} {}'.format(webdata_uri,
                                                              response.status_code,
                                                              response.reason))
    try:
        return response.json()
    except (JSONDecodeError, ValueError) as err:
        sys.exit('Non-JSON response from {}:\n{}'.format(webdata_uri, err))


def get_files_count(webdata_uri, auth=None, headers={}):
    """Return total number of downloadable files."""
    session = make_session(auth, headers)
    webdata = get_webdata(webdata_uri, session)
    session.close()
    return webdata.get('count', None)


def get_files_size(page_uri, auth=None, headers={}):
    """Return total size (bytes) of downloadable files."""
    session = make_session(auth, headers)
    total = 0
    count = 0
    webdata = None
    while page_uri:
        webdata = get_webdata(page_uri, session)
        for f in webdata['files']:
            total += int(f['size'])
        page_uri = webdata.get('next', None)
    if webdata:
        count = webdata.get('count', None)
    session.close()
    return count, total


def convert_bytes(size):
    """Make a human readable size."""
    label = ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB')
    try:
        i = int(math.floor(math.log(size, 1024)))
    except ValueError:
        i = 0
    p = math.pow(1024, i)
    readable_size = round(size/p, 2)
    return '{}{}'.format(readable_size, label[i])


class Downloads:
    """Handles cycling through all of our query results.

    If download is True, we create a queue of the files that need to be
    downloaded. If manifest is True, store the checksums/filenames for
    each available hash algorithm.
    """

    def __init__(self, page_uri, auth=None, download=True, destination='',
                 headers={}):
        self.page_uri = page_uri
        self.auth = auth
        self.download = download
        if self.download:
            self.get_q = multiprocessing.JoinableQueue()
        self.checksums = defaultdict(list)
        self.urls = []
        self.destination = '' if destination == '.' else destination
        self.headers = headers
        self.populate_downloads()

    def populate_downloads(self):
        """Repeat webdata requests to gather downloadable file info."""
        session = make_session(self.auth, self.headers)
        current_uri = self.page_uri
        while current_uri:
            webdata = get_webdata(current_uri, session)
            for f in webdata['files']:
                # Store the first locations URL per file only.
                self.urls.append(f['locations'][0])
                path = os.path.join(self.destination, f['filename'])
                for algorithm, value in f['checksums'].items():
                    self.checksums[algorithm].append((value, path))
                if self.download:
                    df = DataFile(f['locations'], f['filename'], f['checksums'], f['size'])
                    self.get_q.put(df)
            current_uri = webdata.get('next', None)
        session.close()

    def generate_manifests(self):
        """Produce manifest files for all hash algorithms."""
        for algorithm in self.checksums:
            self.write_manifest_file(algorithm)

    def write_manifest_file(self, algorithm):
        """Write a manifest file for the provided algorithm."""
        if algorithm not in self.checksums:
            raise WASAPIManifestError('No values for {}'.format(algorithm))
        manifest_path = os.path.join(self.destination,
                                     'manifest-{}.txt'.format(algorithm))
        with open(manifest_path, 'w') as manifest_f:
            for checksum, path in self.checksums[algorithm]:
                manifest_f.write('{}  {}\n'.format(checksum, path))


class DataFile:
    """Representation of a file to be downloaded.

    `locations` is a list of URLs
    `filename` is the name of the data file
    `size` is the size of the file in bytes
    `checksums` is a dictionary of hash algorithm/value pairs
    `verified` is a Boolean value indicating a successful checksum verification
    """

    def __init__(self, locations, filename, checksums, size):
        self.locations = locations
        self.filename = filename
        self.checksums = checksums
        self.size = size
        self.verified = False


def download_file(data_file, session, output_path):
    """Download webdata file to disk."""
    if check_exists(output_path, data_file.size, data_file.checksums):
        # Don't download the file if it already exists.
        LOGGER.info('{} exists with expected size/checksum'.format(data_file.filename))
        data_file.verified = True
        return data_file
    for location in data_file.locations:
        try:
            response = session.get(location, stream=True)
        except requests.exceptions.RequestException as err:
            # This could be a remote disconnect, read timeout, connection timeout,
            # temporary name resolution issue...
            LOGGER.error('Error downloading {}:\n{}'.format(location, err))
            continue
        msg = '{}: {} {}'.format(location,
                                 response.status_code,
                                 response.reason)
        if response.status_code == 200:
            try:
                write_file(response, output_path)
            except OSError as err:
                LOGGER.error('{}: {}'.format(location, str(err)))
                break
            # Successful download; don't try alternate locations.
            LOGGER.info(msg)
            return data_file
        else:
            LOGGER.error(msg)
    # We didn't download successfully; raise error.
    msg = 'FAILED to download {} from {}'.format(data_file.filename,
                                                 data_file.locations)
    raise WASAPIDownloadError(msg)


def check_exists(path, size, checksums):
    """Check if file with matching size and checksum exists."""
    if not os.path.isfile(path):
        return False
    if not os.path.getsize(path) == size:
        return False
    return verify_file(checksums, path)


def write_file(response, output_path=''):
    """Write file to disk."""
    with open(output_path, 'wb') as wtf:
        for chunk in response.iter_content(1024*4):
            wtf.write(chunk)


def verify_file(checksums, file_path):
    """Verify the file checksum is correct.

    Takes a dictionary of hash algorithms and the corresponding
    expected value for the file_path provided. The first success
    or failure determines if the file is valid.
    """
    for algorithm, value in checksums.items():
        hash_function = getattr(hashlib, algorithm, None)
        if not hash_function:
            # The hash algorithm provided is not supported by hashlib.
            LOGGER.debug('{} is unsupported'.format(algorithm))
            continue
        digest = calculate_sum(hash_function, file_path)
        if digest == value:
            LOGGER.info('Checksum success at: {}'.format(file_path))
            return True
        else:
            LOGGER.error('Checksum {} mismatch for {}: expected {}, got {}'.format(algorithm,
                                                                                   file_path,
                                                                                   value,
                                                                                   digest))
            return False
    # We didn't find a compatible algorithm.
    return False


def calculate_sum(hash_function, file_path):
    """Return the checksum of the given file."""
    hasher = hash_function()
    with open(file_path, 'rb') as rff:
        r = rff.read(READ_LIMIT)
        while r:
            hasher.update(r)
            r = rff.read(READ_LIMIT)
    return hasher.hexdigest()


def convert_queue(tuple_q):
    """Convert a queue containing 2-element tuples into a dictionary.

    The first element becomes a key. The key's value becomes a list
    to which the second tuple element is appended.
    """
    ddict = defaultdict(list)
    while True:
        try:
            key, value = tuple_q.get(block=False)
        except Empty:
            break
        ddict[key].append(value)
    return ddict


def generate_report(result_q):
    """Create a summary of success/failure downloads."""
    results = convert_queue(result_q)
    success = len(results.get('success', []))
    failure = len(results.get('failure', []))
    total = success + failure
    summary = ('Total downloads attempted: {}\n'
               'Successful downloads: {}\n'
               'Failed downloads: {}\n').format(total, success, failure)
    if total != failure and failure > 0:
        summary += 'Failed files (see log for details):\n'
        for filename in results['failure']:
            summary += '    {}\n'.format(filename)
    return summary


class Downloader(multiprocessing.Process):
    """Worker for downloading web files with a persistent session."""

    def __init__(self, get_q, result_q, log_q, log_level=logging.ERROR,
                 auth=None, destination='.', headers={}, *args, **kwargs):
        super(Downloader, self).__init__(*args, **kwargs)
        self.get_q = get_q
        self.result_q = result_q
        self.session = make_session(auth, headers)
        self.destination = destination
        configure_worker_logging(log_q, log_level)

    def run(self):
        """Download files from the queue until there are no more.

        Gets a file's data off the queue, attempts to download the
        file, and puts the result onto another queue.
        """
        while True:
            try:
                data_file = self.get_q.get(block=False)
            except Empty:
                break
            result = 'failure'
            output_path = os.path.join(self.destination, data_file.filename)
            try:
                data_file = download_file(data_file, self.session, output_path)
            except WASAPIDownloadError as err:
                LOGGER.error(str(err))
            else:
                # If we download the file without error, verify the checksum.
                if data_file.verified or verify_file(data_file.checksums, output_path):
                    result = 'success'
            self.result_q.put((result, data_file.filename))
            self.get_q.task_done()


class SetQueryParametersAction(argparse.Action):
    """Store all of the query parameter argument values in a dict."""

    def __call__(self, parser, namespace, values, option_string):
        if not hasattr(namespace, 'query_params'):
            setattr(namespace, 'query_params', {})
        option = option_string.lstrip('-')
        namespace.query_params[option] = values


def _parse_args(args=sys.argv[1:]):
    """Parse the commandline arguments."""
    description = """
        Download WARC files from a WASAPI access point.

        Acceptable date/time formats are:
         2017-01-01
         2017-01-01T12:34:56
         2017-01-01 12:34:56
         2017-01-01T12:34:56Z
         2017-01-01 12:34:56-0700
         2017
         2017-01"""
    try:
        # According to multiprocessing docs, this could fail on some platforms.
        default_processes = multiprocessing.cpu_count()
    except NotImplementedError:
        default_processes = 1
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-b',
                        '--base-uri',
                        dest='base_uri',
                        default='https://partner.archive-it.org/wasapi/v1/webdata',
                        help='base URI for WASAPI access; default: '
                             'https://partner.archive-it.org/wasapi/v1/webdata')
    parser.add_argument('-d',
                        '--destination',
                        default='.',
                        help='location for storing downloaded files')
    parser.add_argument('-l',
                        '--log',
                        help='file to which logging should be written')
    parser.add_argument('-n',
                        '--no-manifest',
                        action='store_true',
                        dest='skip_manifest',
                        help='do not generate checksum files (ignored'
                             ' when used in combination with --manifest)')
    parser.add_argument('-v',
                        '--verbose',
                        action='count',
                        default=0,
                        help='log verbosely; -v is INFO, -vv is DEBUG')

    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument('--profile',
                            dest='profile',
                            help='profile to use for API authentication')
    auth_group.add_argument('-u',
                            '--user',
                            dest='user',
                            help='username for API authentication')
    auth_group.add_argument('-t',
                            '--token',
                            dest='token',
                            help='token for API authentication')

    out_group = parser.add_mutually_exclusive_group()
    out_group.add_argument('-c',
                           '--count',
                           action='store_true',
                           help='print number of files for download and exit')
    out_group.add_argument('-m',
                           '--manifest',
                           action='store_true',
                           help='generate checksum files only and exit')
    out_group.add_argument('-p',
                           '--processes',
                           type=int,
                           default=default_processes,
                           help='number of WARC downloading processes')
    out_group.add_argument('-s',
                           '--size',
                           action='store_true',
                           help='print count and total size of files and exit')
    out_group.add_argument('-r',
                           '--urls',
                           action='store_true',
                           help='list URLs for downloadable files only and exit')

    # Arguments to become part of query parameter string
    param_group = parser.add_argument_group('query parameters',
                                            'parameters for webdata request')
    param_group.add_argument('--collection',
                             action=SetQueryParametersAction,
                             nargs='+',
                             help='collection identifier')
    param_group.add_argument('--filename',
                             action=SetQueryParametersAction,
                             help='exact webdata filename to download')
    param_group.add_argument('--crawl',
                             action=SetQueryParametersAction,
                             help='crawl job identifier')
    param_group.add_argument('--crawl-time-after',
                             action=SetQueryParametersAction,
                             help='request files created on or after this '
                                  'date/time')
    param_group.add_argument('--crawl-time-before',
                             action=SetQueryParametersAction,
                             help='request files created before this date/time')
    param_group.add_argument('--crawl-start-after',
                             action=SetQueryParametersAction,
                             help='request files from crawl jobs starting on '
                                  'or after this date/time')
    param_group.add_argument('--crawl-start-before',
                             action=SetQueryParametersAction,
                             help='request files from crawl jobs starting '
                                  'before this date/time')
    return parser.parse_args(args)


def get_credentials_env():
    """Get API credentials from environment variables."""
    env = os.environ.get
    auth = (env('WASAPI_USER'), env('WASAPI_PASS'))
    if None in auth:
        auth = None
    else:
        LOGGER.debug('Using API credentials from environment variables')
    return auth


def get_credentials_config(profile, path=PROFILE_PATH):
    """Get API credentials from a config file."""
    config = configparser.ConfigParser()
    try:
        config.read_file(open(path))
        auth = (config.get(profile, 'username'),
                config.get(profile, 'password'))
    except (OSError,
            configparser.NoSectionError,
            configparser.NoOptionError) as err:
        sys.exit('{}: please create config file to supply API credentials with format:\n\n'
                 '[{}]\n'
                 'username = someuser\n'
                 'password = secretpasswd\n'.format(err, profile))
    LOGGER.debug('Using API credentials from {}'.format(path))
    return auth


def get_credentials(user=None, profile=None):
    """Determine a username/password combination if one is supplied.

    Order of precedence is command line, environment, config file."""
    auth = None
    if user:
        # If there is a username, prompt for a password.
        auth = (user, getpass.getpass())
    else:
        # Check for credentials in environment variables.
        auth = get_credentials_env()
    if profile and auth is None:
        # Check for credentials in a config file.
        auth = get_credentials_config(profile)
    return auth


def main():
    args = _parse_args()

    if (not os.access(args.destination, os.W_OK)
            and not args.size
            and not args.count):
        msg = 'Cannot write to destination: {}'.format(args.destination)
        sys.exit(msg)

    # Start log writing process.
    manager = multiprocessing.Manager()
    log_q = manager.Queue()
    try:
        listener = start_listener_logging(log_q, args.log)
    except OSError as err:
        print('Could not open file for logging:', err)
        sys.exit(1)

    @atexit.register
    def stop_listener_logging():
        """Stop listener when exiting program normally."""
        listener.stop()

    # Configure a logger for the main process.
    try:
        log_level = [logging.ERROR, logging.INFO, logging.DEBUG][args.verbose]
    except IndexError:
        log_level = logging.DEBUG
    configure_main_logging(log_q, log_level)

    # Generate query string for the webdata request.
    try:
        query = '?{}'.format(urlencode(args.query_params, safe=':', doseq=True))
    except AttributeError:
        # Use empty query if user didn't enter any query parameters.
        query = ''
    webdata_uri = '{}{}'.format(args.base_uri, query)

    # Set up authentication.
    auth = None
    headers = {}
    if args.token:
        # Set the HTTP Authentication header.
        headers['Authorization'] = 'Token {}'.format(args.token)
    else:
        # Generate authentication tuple for the API calls.
        auth = get_credentials(args.user, args.profile)

    # If user wants the size, don't download files.
    if args.size:
        count, size = get_files_size(webdata_uri, auth, headers)
        print('Number of Files: ', count)
        print('Size of Files: ', convert_bytes(size))
        sys.exit()

    # If user wants a count, don't download files.
    if args.count:
        print('Number of Files: ', get_files_count(webdata_uri, auth, headers))
        sys.exit()

    # Process webdata requests to generate checksum files.
    if args.manifest:
        downloads = Downloads(webdata_uri, auth, download=False,
                              destination=args.destination, headers=headers)
        downloads.generate_manifests()
        sys.exit()

    # Print the URLs for files that can be downloaded; don't download them.
    if args.urls:
        downloads = Downloads(webdata_uri, auth, download=False,
                              destination=args.destination, headers=headers)
        for url in downloads.urls:
            print(url)
        sys.exit()

    # Process webdata requests to fill webdata file queue.
    downloads = Downloads(webdata_uri, auth, download=True,
                          destination=args.destination, headers=headers)

    # Write manifest file(s).
    if not args.skip_manifest:
        downloads.generate_manifests()

    # Download with multiple processes.
    get_q = downloads.get_q
    result_q = manager.Queue()

    download_processes = []
    try:
        num_processes = min(args.processes, get_q.qsize())
    except NotImplementedError:
        num_processes = args.processes
    for _ in range(num_processes):
        dp = Downloader(get_q, result_q, log_q, log_level, auth,
                        args.destination, headers=headers)
        dp.start()
        download_processes.append(dp)
    for dp in download_processes:
        dp.join()
    get_q.join()

    print(generate_report(result_q))


if __name__ == '__main__':
    main()
