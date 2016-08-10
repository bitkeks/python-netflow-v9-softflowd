# Python NetFlow v9 parser and UDP collector
This script is able to parse incoming UDP NetFlow packets of **NetFlow version 9**.

Version 9 is the first NetFlow version using templates.
Templates make dynamically sized and configured NetFlow data flowsets possible,
which makes the collector's job harder.

## Resources
* [Cisco NetFlow v9 paper](http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html)
* [RFC "Cisco Systems NetFlow Services Export Version 9"](https://tools.ietf.org/html/rfc3954)

## Development environment
I have specifically written this script in combination with NetFlow exports from
[softflowd](https://github.com/djmdjm/softflowd) v0.9.9
