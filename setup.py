#!/usr/bin/env python
from setuptools import setup, find_packages
import os


data_files = [(d, [os.path.join(d, f) for f in files])
              for d, folders, files in os.walk(os.path.join('src', 'config'))]

setup(name='python-netflow-v9-softflowd',
      version='1.0',
      description='NetFlow v9 parser and collector implemented in Python 3. Developed to be used with softflowd v0.9.9',
      author='coox',
      author_email='gro.rotarocedten@mod',
      packages=find_packages('src'),
      package_dir={'': 'src'},
)
