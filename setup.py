#!/usr/bin/env python3

from setuptools import setup
import os

setup(name='netflow',
      version='0.7.0',
      description='NetFlow v1, v5, and v9 parser and collector implemented in Python 3. Developed to be used with softflowd v0.9.9',
      author='Dominik Pataky',
      author_email='dev@bitkeks.eu',
      packages=["netflow"],
      license='MIT'
)
