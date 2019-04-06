# encoding: utf-8

import select
import socket
import struct
from socketserver import ThreadingMixIn
from socketserver import TCPServer
from socketserver import StreamRequestHandler

import constants
import log


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):
    username = 'stunnerlw'
    password = 'oliver9972'

    def handle(self):
        log.info('Accepting connection from %s:%s' % self.client_address)

        # greeting header
        # read and unpack 2 bytes from a client, sample: b'\x05\x01'
        header = self.connection.recv(constants.RECEIVE_HEADER_LENGTH)
        version, nmethods = struct.unpack("!BB", header)
        log.info("socket version: %s, nmethods:%s" % (version, nmethods))
        # if not socks 5 raise exception
        assert version == constants.SOCKS_VERSION
        # if length of request < 1 raise exception
        assert nmethods > 0
        # get available methods
        methods = self.get_available_methods(nmethods)
        log.info("get_available_methods: %s" % methods)

        # accept only USERNAME/PASSWORD auth
        if 2 not in set(methods):
            # close connection
            self.server.close_request(self.request)
            return

        # send welcome message
        self.connection.sendall(struct.pack(
            "!BB", constants.SOCKS_VERSION, constants.RESPONSE_FOR_AUTH))
        log.debug("send request successfully message.")

        if not self.verify_credentials():
            log.error("verify_credentials failed!")
            return

        # request
        version, cmd, _, address_type = struct.unpack(
            "!BBBB", self.connection.recv(4))
        assert version == constants.SOCKS_VERSION

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:  # Domain name
            doamin_name = self.connection.recv(1)
            log.debug("doamin_name:%s" % doamin_name)
            domain_length = doamin_name[0]
            address = self.connection.recv(domain_length)

        port = struct.unpack('!H', self.connection.recv(2))[0]

        # reply
        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                log.info('Connected to %s %s' % (address, port))
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", constants.SOCKS_VERSION, 0, 0, address_type,
                                addr, port)

        except Exception as err:
            log.error(err)
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
        log.debug("get_version:%s" % version)
        assert version == constants.RESPONSE_FOR_AUTH_VERSION

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode("utf-8")
        log.debug("for debug. username_len:%s, username:%s" %
                  (username_len, username))
        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')
        log.debug("for debug. password_len:%s, password:%s" %
                  (password_len, password))

        if username == self.username and password == self.password:
            # success, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        response = struct.pack("!BB", version, 0xFF)
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


if __name__ == '__main__':
    with ThreadingTCPServer(('', 8080), SocksProxy) as server:
        server.serve_forever()
