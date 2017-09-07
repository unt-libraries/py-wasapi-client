#!/usr/bin/env python

from setuptools import setup


setup(
    name='py-wasapi-client',
    version='0.1',
    url='https://github.com/unt-libraries/py-wasapi-client',
    author='University of North Texas Libraries',
    license='BSD',
    py_modules=['wasapi_client'],
    scripts=['wasapi_client.py'],
    description='A client for the [Archive-It] WASAPI Data Transer API',
    install_requires=['requests>=2.18.1'],
    entry_points={
        'console_scripts': [
            'wasapi-client=wasapi_client:main'
        ]
    },
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    classifiers=[
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Communications :: File Sharing',
    ],
)
