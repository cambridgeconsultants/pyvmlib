"""Setup config for pyvmlib."""

from setuptools import setup

setup(name='pyvmlib',
      version='1.0.0',
      description='A simple library for controlling VMware vCenter / ESXi servers.',
      url='http://github.com/cambridgeconsultants/pyvmlib',
      author='Cambridge Consultants',
      author_email='jonathan.pallant@cambridgeconsultants.com',
      license='Apache-2.0',
      install_requires=[
        'pyvmomi',
      ],
      packages=['pyvmlib'],
      zip_safe=False)
