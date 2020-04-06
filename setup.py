#!/usr/bin/env python3

from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='netflow',
    version='0.10.2',
    description='NetFlow v1, v5, v9 and IPFIX tool suite implemented in Python 3',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Dominik Pataky',
    author_email='dev@bitkeks.eu',
    url='https://github.com/bitkeks/python-netflow-v9-softflowd',
    packages=["netflow"],
    license='MIT',
    python_requires='>=3.5',
    keywords='netflow ipfix collector parser',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators"
    ],
)
