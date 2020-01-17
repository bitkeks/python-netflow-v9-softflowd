# Python NetFlow v9 parser and UDP collector
This script is able to collect and parse incoming UDP NetFlow packets of **NetFlow versions 1, 5 and 9**.

Version 9 is the first NetFlow version using templates.
Templates make dynamically sized and configured NetFlow data flowsets possible,
which makes the collector's job harder.

Copyright 2016-2019 Dominik Pataky <dev@bitkeks.eu>

Licensed under MIT License. See LICENSE.


## Using the collector and analyzer
In this repo you also find `main.py` and `analyze_json.py`.

To start an example collector run `python3 main.py -p 9000 -D`. This will run
a collector at port 9000 in debug mode. Point your flow exporter to this port on
your host and after some time the first ExportPackets should appear (the flows
need to expire first).

After you collected some data, `main.py` exports them into GZIP files, simply
named `<timestamp>.gz`.

To analyze the saved traffic, run `analyze_json.py -f <gzip file>`. In my example
script this will look like the following, with resolved hostnames and services, transfered bytes and connection duration:

    2017-10-28 23:17.01: SSH     | 4.25M    | 15:27 min | localmachine-2 (<IPv4>) to localmachine-1 (<IPv4>)
    2017-10-28 23:17.01: SSH     | 4.29M    | 16:22 min | remotemachine (<IPv4>) to localmachine-2 (<IPv4>)
    2017-10-28 23:19.01: HTTP    | 22.79M   | 47:32 min | uwstream3.somafm.com (173.239.76.148) to localmachine-1 (<IPv4>)
    2017-10-28 23:22.01: HTTPS   | 1.21M    | 3 sec     | fra16s12-in-x0e.1e100.net (2a00:1450:4001:818::200e) to localmachine-1 (<IPv6>)
    2017-10-28 23:23.01: SSH     | 93.79M   | 21 sec    | remotemachine (<IPv4>) to localmachine-2 (<IPv4>)
    2017-10-28 23:51.01: SSH     | 14.08M   | 1:23.09 hours | remotemachine (<IPv4>) to localmachine-2 (<IPv4>)

Feel free to customize the analyzing script, e.g. make it print some
nice graphs or calculate broader statistics.

## Resources
* [Cisco NetFlow v9 paper](http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html)
* [RFC "Cisco Systems NetFlow Services Export Version 9"](https://tools.ietf.org/html/rfc3954)

## Development environment
I have specifically written this script in combination with NetFlow exports from
[softflowd](https://github.com/djmdjm/softflowd) v0.9.9 - it should work with every
correct NetFlow v9 implementation though.

### Running tests
The file `tests.py` contains some tests based on real softflowd export packets.
To create the test packets try the following:

  1. Run tcpdump/Wireshark on your interface
  2. Produce some sample flows, e.g. surf the web and refresh your mail client.
  3. Save the pcap file to disk.
  4. Run tcpdump/Wireshark again on an interface.
  4. Run softflowd with the `-r <pcap_file>` flag. softflowd reads the captured traffic, produces the flows and exports them. Use the interface you are capturing packets on to send the exports.
  5. Examine the captured traffic. Use Wireshark and set the `CFLOW` "decode as" dissector on the export packets (e.g. based on the port). The `data` fields should then be shown correctly as Netflow payload.
  6. Extract this payload as hex stream. Anonymize the IP addresses with a hex editor if necessary. A recommended hex editor is [bless](https://github.com/afrantzis/bless).

The collector is run in a background thread. The difference in transmission speed from the exporting client can lead to different results, possibly caused by race conditions during the usage of the GZIP output file.
