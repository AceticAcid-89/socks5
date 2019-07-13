# encoding: utf-8

import argparse
import getpass
import logging
import platform
import select
import socket
import struct
from socketserver import ThreadingMixIn
from socketserver import TCPServer
from socketserver import StreamRequestHandler
import traceback

import constants


parser = argparse.ArgumentParser()
parser.add_argument("-ip", "-i", action="store", type=str, required=True,
                    help="ip for proxy-server", dest="proxy_ip")
parser.add_argument("-port", "-p", action="store", type=int, required=True,
                    help="port for proxy server", dest="proxy_port")
parser.add_argument("-user", "-u", action="store", type=str, required=True,
                    help="username for proxy server", dest="username")
parser.add_argument("-pwd", "-w", action="store", type=str, required=True,
                    help="password for proxy server", dest="password")
args = parser.parse_args()

proxy_ip = args.proxy_ip
proxy_port = args.proxy_port


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):
    username = args.username
    password = args.password

    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address)

        # greeting header
        # read and unpack 2 bytes from a client, sample: b'\x05\x01'
        header = self.connection.recv(constants.RECEIVE_HEADER_LENGTH)
        version, nmethods = struct.unpack("!BB", header)
        logging.info("socket version: %s, nmethods:%s" % (version, nmethods))
        # if not socks 5 raise exception
        assert version == constants.SOCKS_VERSION
        # if length of request < 1 raise exception
        assert nmethods > 0
        # get available methods
        methods = self.get_available_methods(nmethods)
        logging.info("get_available_methods: %s" % methods)

        # accept only USERNAME/PASSWORD auth
        if constants.REQUEST_WITH_AUTH not in set(methods):
            # close connection
            self.server.close_request(self.request)
            return

        # send welcome message
        welcome_bytes = struct.pack(
            "!BB", constants.SOCKS_VERSION, constants.RESPONSE_FOR_AUTH)
        self.connection.sendall(welcome_bytes)
        logging.debug("send welcome message ends.")

        if not self.verify_credentials():
            logging.error("verify_credentials failed!")
            return

        # client connect request
        # b'\x05\x01\x00\x03'
        version, cmd, _, address_type = struct.unpack(
            "!BBBB", self.connection.recv(4))
        assert version == constants.SOCKS_VERSION

        # IPv4
        if address_type == constants.ATYP_IP:
            request_address = socket.inet_ntoa(self.connection.recv(4))
        # Domain name
        elif address_type == constants.ATYP_DOMAIN:
            domain_length = ord(self.connection.recv(1))
            request_address = self.connection.recv(domain_length)
            logging.debug("request_address:%s" % request_address)
        else:
            # for ipv6
            logging.error("not support ipv6 now")
            self.server.close_request(self.request)
            return
        # (443,)
        request_port = struct.unpack('!H', self.connection.recv(2))[0]
        logging.debug("request_port:%s" % request_port)

        # reply
        remote = None
        try:
            # CONNECT
            if cmd == constants.CMD_CONNECT:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((request_address, request_port))
                bind_address = remote.getsockname()
                logging.info('Connected to %s %s, bind_address: %s' %
                             (request_address, request_port, bind_address))
            else:
                self.server.close_request(self.request)
                logging.error("only support connection type of CONNECT, request is %s" % cmd)
                return

            bind_ip_32 = struct.unpack(
                "!I", socket.inet_aton(bind_address[0]))[0]
            bind_port = bind_address[1]
            reply = struct.pack("!BBBBIH", constants.SOCKS_VERSION,
                                constants.RESPONSE_SUCCESS, constants.RSV,
                                address_type, bind_ip_32, bind_port)

        except Exception as err:
            logging.error(err)
            # return connection refused error
            reply = self.generate_failed_reply(
                address_type, constants.REQUEST_REFUSED)

        self.connection.sendall(reply)

        # establish data exchange
        if reply[1] == constants.RESPONSE_SUCCESS and \
                cmd == constants.CMD_CONNECT:
            try:
                self.exchange_loop(self.connection, remote)
            except Exception:
                logging.error("exchange_loop failed! traceback:%s" %
                              traceback.format_exc())

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):
        version = ord(self.connection.recv(1))
        logging.debug("get_version:%s" % version)
        assert version == constants.RESPONSE_FOR_AUTH_VERSION

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode("utf-8")
        logging.debug("for debug. username_len:%s, username:%s" %
                      (username_len, username))
        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')
        logging.debug("for debug. password_len:%s, password:%s" %
                      (password_len, password))

        if username == self.username and password == self.password:
            # auth success, status = 0
            auth_success_bytes = struct.pack(
                "!BB", version, constants.AUTH_SUCCESS)
            self.connection.sendall(auth_success_bytes)
            return True

        # failure, status != 0
        response = struct.pack("!BB", version, constants.AUTH_FAIL)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        logging.error("verify_credentials fails, close request!")
        return False

    @staticmethod
    def generate_failed_reply(address_type, error_number):
        return struct.pack("!BBBBIH", constants.SOCKS_VERSION, error_number,
                           0, address_type, 0, 0)

    @staticmethod
    def exchange_loop(client, remote):
        logging.info("enter in exchange_loop")
        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                logging.debug("client: %s for reading" % client)
                data = client.recv(constants.MAX_RECEIVE_BYTES)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                logging.debug("remote: %s for reading" % remote)
                data = remote.recv(constants.MAX_RECEIVE_BYTES)
                if client.send(data) <= 0:
                    break


class Logger(object):

    @staticmethod
    def init():
        windows_log_path = "C:\\Users\\%s\\Desktop\\socks_proxy.log"
        linux_log_path = "/var/log/socks_proxy.log"
        run_platform = platform.platform()
        if run_platform.startswith("Windows"):
            user = getpass.getuser()
            log_path = windows_log_path % user
        else:
            log_path = linux_log_path

        log_format = '[%(asctime)s %(filename)s:%(lineno)d' \
                     ' %(funcName)s] [PID:%(thread)d] ' \
                     '[%(threadName)s] [%(levelname)s] %(message)s'
        date_format = '%Y-%m-%dT%H:%M:%S'
        logging.basicConfig(level=logging.DEBUG,
                            format=log_format,
                            datefmt=date_format,
                            filename=log_path)


if __name__ == '__main__':
    Logger.init()
    with ThreadingTCPServer(
            (proxy_ip, proxy_port), SocksProxy) as server:
        server.serve_forever()
