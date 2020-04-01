#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2016-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""
import gzip
import json
import subprocess
import sys
import unittest

from tests.lib import *


class TestFlowExportAnalyzer(unittest.TestCase):
    def test_analyzer(self):
        """Test the analyzer by producing some packets, parsing them and then calling the analyzer
        in a subprocess, piping in a created gzip JSON collection (as if it is coming from a file).
        """
        # First create and parse some packets, which should get exported
        pkts, _, _ = send_recv_packets([PACKET_V9_TEMPLATE, *PACKETS_V9])

        # Now the pkts must be transformed from their data structure to the "gzipped JSON representation",
        # which the collector uses for persistant storage.
        data_dicts = []  # list holding all entries
        for p in pkts:  # each pkt has its own entry with timestamp as key
            data_dicts.append({p.ts: {
                "client": p.client,
                "header": p.export.header.to_dict(),
                "flows": [f.data for f in p.export.flows]
            }})
        data = "\n".join([json.dumps(dd) for dd in data_dicts])  # join all entries together by newlines

        # Different stdout/stderr arguments for backwards compatibility
        pipe_output_param = {"capture_output": True}
        if sys.version_info < (3, 7):  # capture_output was added in Python 3.7
            pipe_output_param = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE
            }

        # Analyzer takes gzipped input either via stdin or from a file (here: stdin)
        gzipped_input = gzip.compress(data.encode())  # encode to unicode

        # Run analyzer as CLI script with no packets ignored (parameter)
        analyzer = subprocess.run(
            [sys.executable, '-m', 'netflow.analyzer', '-p', '0'],
            input=gzipped_input,
            **pipe_output_param
        )

        # If stderr has content, print it
        # make sure there are no errors
        self.assertEqual(analyzer.stderr, b"", analyzer.stderr.decode())

        # Every 2 flows are written as a single line (any extras are dropped)
        num_flows = sum(len(list(item.values())[0]["flows"]) for item in data_dicts)
        self.assertEqual(len(analyzer.stdout.splitlines()) - 2, num_flows // 2)  # ignore two header lines


if __name__ == '__main__':
    unittest.main()
