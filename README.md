# Python NetFlow v9 parser and UDP collector
This script is able to parse incoming UDP NetFlow packets of **NetFlow version 9**.

Version 9 is the first NetFlow version using templates.
Templates make dynamically sized and configured NetFlow data flowsets possible,
which makes the collector's job harder.

## Using the collector and analyzer
In this repo you also find `main.py` and `analyze_json.py`.

To start an example collector run `python3 main.py -p 9000 -D`. This will run
a collector at port 9000 in debug mode. Point your flow exporter to this port on
your host and after some time the first ExportPackets should appear (the flows
need to expire first).

After you collected some data, `main.py` exports them into JSON files, simply
named `<timestamp>.json`.

To analyze the saved traffic, run `analyze_json.py <json file>`. In my example
script this will look like the following, with flows filtered for a size bigger
than one megabyte and with resolved hostnames and services:

    2017-10-28 23:17.01: SSH from localmachine-1 (<IPv4>) to localmachine-2 (<IPv4>) size 4.25M
    2017-10-28 23:19.01: HTTP from uwstream3.somafm.com (173.239.76.148) to localmachine-2 (<IPv4>) size 22.79M
    2017-10-28 23:22.01: HTTPS from fra16s12-in-x0e.1e100.net (2a00:1450:4001:818::200e) to localmachine-2 (<IPv6>) size 1.21M
    2017-10-28 23:32.01: HTTPS from fra16s12-in-x0e.1e100.net (2a00:1450:4001:818::200e) to localmachine-2 (<IPv6>) size 1.60M
    2017-10-28 23:32.01: HTTPS from fra16s14-in-x0e.1e100.net (2a00:1450:4001:81a::200e) to localmachine-2 (<IPv6>) size 3.01M
    2017-10-28 23:44.28: HTTP from localmachine-3 (<IPv4>) to localmachine-2 (<IPv4>) size 2.00G

Feel free to customize the analyzing script, e.g. make it print some
nice graphs or calculate broader statistics.

## Resources
* [Cisco NetFlow v9 paper](http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html)
* [RFC "Cisco Systems NetFlow Services Export Version 9"](https://tools.ietf.org/html/rfc3954)

## Development environment
I have specifically written this script in combination with NetFlow exports from
[softflowd](https://github.com/djmdjm/softflowd) v0.9.9 - it should work with every
correct NetFlow v9 implementation though.
