#!/usr/bin/env python3
from setuptools import setup, find_packages
import os

data_files = [(d, [os.path.join(d, f) for f in files])
              for d, folders, files in os.walk(os.path.join('src', 'config'))]

setup(name='netflow-v9',
      version='0.5',
      description='NetFlow v9 parser and collector implemented in Python 3. Developed to be used with softflowd v0.9.9',
      author='Dominik Pataky',
      author_email='dom@netdecorator.org',
      packages=find_packages('src'),
      package_dir={'': 'src'},
)
