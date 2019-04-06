# encoding: utf-8

import getpass
import logging
import platform
import select
import socket
import struct
from socketserver import ThreadingMixIn
from socketserver import TCPServer
from socketserver import StreamRequestHandler

import constants


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):
    username = 'username'
    password = 'password'

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
        elif address_type == 3:
            domain_length = ord(self.connection.recv(1))
            request_address = self.connection.recv(domain_length)
            logging.debug("request_address:%s" % request_address)
        else:
            # for ipv6
            logging.error("not support ipv6 now")
            return
        # (443,)
        request_port = struct.unpack('!H', self.connection.recv(2))[0]

        # reply
        try:
            # CONNECT
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((request_address, request_port))
                bind_address = remote.getsockname()
                logging.info('Connected to %s %s, bind_address: %s' %
                             (request_address, request_port, bind_address))
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", constants.SOCKS_VERSION,
                                0, 0, address_type, addr, port)

        except Exception as err:
            logging.error(err)
            # return connection refused error
            reply = self.generate_failed_reply(address_type, 5)

        self.connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)

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
        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", constants.SOCKS_VERSION, error_number,
                           0, address_type, 0, 0)

    def exchange_loop(self, client, remote):

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break


class Logger(object):

    def init(self):
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
    Logger().init()
    with ThreadingTCPServer(('', 8080), SocksProxy) as server:
        server.serve_forever()
