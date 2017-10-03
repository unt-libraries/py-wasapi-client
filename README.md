# py-wasapi-client [![Build Status](https://travis-ci.org/unt-libraries/py-wasapi-client.svg)](https://travis-ci.org/unt-libraries/py-wasapi-client)
A client for the [Archive-It] WASAPI Data Transfer API. This client
is being developed according to the [ait-specification](https://github.com/WASAPI-Community/data-transfer-apis/tree/master/ait-specification).

## Requirements

* Python 3.4, 3.5, or 3.6

## Installation

The WASAPI client may be installed with:

```
 $ python setup.py install
```

Once installed, run the client at the commandline with:

```
 $ wasapi-client --help
```

That gives you usage instructions:

```
usage: wasapi-client [-h] [-b BASE_URI] [-d DESTINATION] [-l LOG] [-n] [-v]
                     [--profile PROFILE] [-c | -m | -p PROCESSES | -s | -r]
                     [--collection COLLECTION [COLLECTION ...]]
                     [--filename FILENAME] [--crawl CRAWL]
                     [--crawl-time-after CRAWL_TIME_AFTER]
                     [--crawl-time-before CRAWL_TIME_BEFORE]
                     [--crawl-start-after CRAWL_START_AFTER]
                     [--crawl-start-before CRAWL_START_BEFORE]

        Download WARC files from a WASAPI access point.

        Acceptable date/time formats are:
         2017-01-01
         2017-01-01T12:34:56
         2017-01-01 12:34:56
         2017-01-01T12:34:56Z
         2017-01-01 12:34:56-0700
         2017
         2017-01

optional arguments:
  -h, --help            show this help message and exit
  -b BASE_URI, --base-uri BASE_URI
                        base URI for WASAPI access; default:
                        https://partner.archive-it.org/wasapi/v1/webdata
  -d DESTINATION, --destination DESTINATION
                        location for storing downloaded files
  -l LOG, --log LOG     file to which logging should be written
  -n, --no-manifest     do not generate checksum files (ignored when used in
                        combination with --manifest)
  -v, --verbose         log verbosely; -v is INFO, -vv is DEBUG
  --profile PROFILE     profile to use for API authentication
  -c, --count           print number of files for download and exit
  -m, --manifest        generate checksum files only and exit
  -p PROCESSES, --processes PROCESSES
                        number of WARC downloading processes
  -s, --size            print count and total size of files and exit
  -r, --urls            list URLs for downloadable files only and exit

query parameters:
  parameters for webdata request

  --collection COLLECTION [COLLECTION ...]
                        collection identifier
  --filename FILENAME   exact webdata filename to download
  --crawl CRAWL         crawl job identifier
  --crawl-time-after CRAWL_TIME_AFTER
                        request files with date of creation after this date
  --crawl-time-before CRAWL_TIME_BEFORE
                        request files with date of creation before this date
  --crawl-start-after CRAWL_START_AFTER
                        request files from crawl jobs starting after this date
  --crawl-start-before CRAWL_START_BEFORE
                        request files from crawl jobs starting before this
                        date
```

## Configuration

When you are using the tool to query an Archive-It WASAPI endpoint,
you will need to supply a profile `--profile` from the configuration
file. The configuration file should be at `~/.wasapi-client`.

An example profile:

```
[unt]
username = exampleUser
password = examplePassword
```

## Example Usage

The following command downloads the WARC files available from a crawl
with `crawl id` 256119 and logs program output to a file named
`out.log`. Downloads are carried out by one process.

```
 $ wasapi-client --profile unt --crawl 256119 --log out.log -p 1
```

The following command downloads the WARC files available from crawls
that occurred in the specified time range. Verbose logging is being
written to a file named out.log. Downloads are happening via four
processes and written to a directory at /tmp/wasapi_warcs/.

```
 $ wasapi-client --profile unt --crawl-start-after 2016-12-22T13:01:00 --crawl-start-before 2016-12-22T15:11:00  -vv --log out.log -p 4 -d /tmp/wasapi_warcs/

```

The following command produces the size and file count of all content
available to the user.

```
 $ wasapi-client --profile unt -s 
```

The following command gives the user the number of files available by
the given query parameters.

```
 $ wasapi-client --profile unt --crawl 256119 -c 
```

The following command downloads the file called example.warc.gz to
the current working directory.

```
$ wasapi-client --profile unt --filename example.warc.gz
```

By default, manifest files are generated to provide checksums for the
files to be downloaded. One manifest file is generated for each hash algorithm
provided by the WASAPI access point. The manifest files are written to the
download destination. If you don't want manifest files, use the --no-manifest
flag.

```
$ wasapi-client --profile unt --crawl 256119 --log out.log --no-manifest
```

If you want to generate manifest files for your available webdata files
without actually downloading the webdata files, use the --manifest flag.

```
$ wasapi-client --profile unt --crawl 256119 --manifest
```

If you would like to produce a list of URLs where your webdata files can
later be downloaded by another tool (such as wget) rather than having
wasapi-client do the downloading, use the --urls flag.

```
$ wasapi-client --profile unt --crawl 256119 --urls
```

## Run the Tests

```
$ python setup.py test
```

or

```
$ tox
```
