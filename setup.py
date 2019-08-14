#!/usr/bin/env python

from setuptools import setup


with open('README.md', 'r') as readme_f:
    long_description = readme_f.read()


setup(
    name='py-wasapi-client',
    version='1.0.0',
    url='https://github.com/unt-libraries/py-wasapi-client',
    author='University of North Texas Libraries',
    author_email='lauren.ko@unt.edu',
    license='BSD',
    py_modules=['wasapi_client'],
    scripts=['wasapi_client.py'],
    description='A client for the [Archive-It] WASAPI Data Transer API',
    long_description=long_description,
    long_description_content_type='text/markdown',
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
        'Programming Language :: Python :: 3.7',
        'Topic :: Communications :: File Sharing',
    ],
)
