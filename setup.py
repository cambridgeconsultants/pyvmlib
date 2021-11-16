"""Setup config for pyvmlib."""

import os
from setuptools import setup


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as fn:
        return fn.read()


setup(
    name='pyvmlib',
    version='2.4.1',
    description='A simple library for controlling VMware vSphere servers.',
    # NOTE: pypi prefers the use of RST to render docs
    long_description=read('README.rst'),
    url='http://github.com/cambridgeconsultants/pyvmlib',
    author='Cambridge Consultants',
    author_email='vicky.larmour@cambridgeconsultants.com',
    license='Apache-2.0',
    install_requires=[
        'pyvmomi',
        'requests',
        'six',
    ],
    packages=['pyvmlib'],
    classifiers=[
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'Environment :: No Input/Output (Daemon)',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Distributed Computing',
    ],
    keywords=['pyvmlib', 'pyvmomi', 'vsphere', 'vmware', 'esxi'],
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*',
    zip_safe=False
)
