#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2016-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""
# TODO: tests with 500 packets fail with delay=0. Probably a problem with UDP sockets buffer

import ipaddress
import random
import unittest

from tests.lib import *


class TestFlowExportIPFIX(unittest.TestCase):
    pass
