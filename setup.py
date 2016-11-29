#!/usr/bin/env python
from setuptools import setup, find_packages
import sys, os
from distutils import versionpredicate

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()


version = '0.1.0'

install_requires = [
    'secretsharing', 'pyscard'
]

setup(name='pycardshare',
    version=version,
    description="shamir secret sharing using memory (EEPROM) cards",
    long_description=README,
    classifiers=[
      # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    ],
    keywords='secret sharing memory cards smartcard',
    author='Leif Johansson',
    author_email='leifj@sunet.se',
    url='http://blogs.mnt.se',
    license='BSD',
    packages=find_packages('.'),
    setup_requires=['nose>=1.0'],
    tests_require=['nose>=1.0', 'mock'],
    test_suite="nose.collector",
    package_dir = {'': '.'},
    include_package_data=True,
    package_data = {
    },
    zip_safe=False,
    install_requires=install_requires,
    requires=install_requires,
    entry_points={
          'console_scripts': ['cardshare=cardshare.tools:cardshare', 'keyshare=cardshare.tools:keyshare']
    },
)
