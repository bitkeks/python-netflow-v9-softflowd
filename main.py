import logging
import argparse
import sys
import SocketServer
from netflow.collector_v9 import ExportPacket

logging.getLogger().setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(message)s')
ch.setFormatter(formatter)
logging.getLogger().addHandler(ch)

parser = argparse.ArgumentParser(description='A sample netflow collector.')

parser.add_argument('-chost', type=str, default='',
                    help='collector listening address')
parser.add_argument('-cport', type=int, default=2055,
                    help='collector listener port')


class SoftflowUDPHandler(SocketServer.BaseRequestHandler):
    # We need to save the templates our NetFlow device
    # send over time. Templates are not resended every
    # time a flow is sent to the collector.
    TEMPLATES = {}

    @classmethod
    def get_server(cls, host, port):
        logging.info("Listening on interface {}:{}".format(host, port))
        server = SocketServer.UDPServer((host, port), cls)
        return server

    def handle(self):
        data = self.request[0]
        host = self.client_address[0]
        s = "Received data from {}, length {}".format(host, len(data))
        logging.info(s)
        export = ExportPacket(data, self.TEMPLATES)
        self.TEMPLATES.update(export.templates)
        s = "Processed ExportPacket with {} flows.".format(export.header.count)
        logging.info(s)
        return export

if __name__ == "__main__":
    args = parser.parse_args()
    server = SoftflowUDPHandler.get_server(args.chost, args.cport)

    try:
        logging.debug("Starting the NetFlow listener")
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        raise
