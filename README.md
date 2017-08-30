# py-wasapi-client [![Build Status](https://travis-ci.org/unt-libraries/py-wasapi-client.svg)](https://travis-ci.org/unt-libraries/py-wasapi-client)
A client for the [Archive-It] WASAPI Data Transfer API. This client
is being developed according to the [ait-specification](https://github.com/WASAPI-Community/data-transfer-apis/tree/master/ait-specification).

## Requirements

* Python 3.5 or 3.6

## Installation

The WASAPI client may be installed with:

```
 $ python setup.py install
```

Once installed, run the client at the commandline with:

```
 $ wasapi-client --help
```

If you are running this to access the Archive-It WASAPI endpoint,
you will need to supply a username with `-u`, and you will be prompted
for a password.

## Example Usage

The following command downloads the WARC files available from a crawl
with `crawl id` 256119 and logs program output to a file named
`out.log`. Downloads are carried out by one process.

```
 $ wasapi-client -u user.name --crawl 256119 --log out.log -p 1
```

The following command downloads the WARC files available from crawls
that occurred in the specified time range. Verbose logging is being
written to a file named out.log. Downloads are happening via four
processes and written to a directory at /tmp/wasapi_warcs/.

```
 $ wasapi-client -u user.name --crawl-start-after 2016-12-22T13:01:00 --crawl-start-before 2016-12-22T15:11:00  -vv --log out.log -p 4 -d /tmp/wasapi_warcs/

```

The following command produces the size and file count of all content
available to the user.

```
 $ wasapi-client -u user.name -s 
```

The following command gives the user the number of files available by
the given query parameters.

```
 $ wasapi-client -u user.name --crawl 256119 -c 
```

The following command downloads the file called example.warc.gz.

```
$ wasapi-client -u user.name --filename example.warc.gz
```

## Run the Tests

 $ python setup.py test
