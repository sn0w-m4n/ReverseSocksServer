# -*- coding: utf-8 -*-
#########################################################################
# File Name: sockserver.py
# Author: Ted
# mail: httpconnection@gmail.com 
# Created Time: 二  7/14 18:38:48 2020
#########################################################################
#!env python
import sys
import logging
import select
import socket
import struct
import getopt
try:
    import threading
except ImportError:
    import dummy_threading as threading
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler, BaseServer

logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5

def usage():
    print("Usage: %s create reverse socks server after firewall\n\
    work as relay: -r -p proxy_port -l relay_port\n\
    work as reverse socks in firewall: -s -h relay_host -p relay_port\n" % sys.argv[0])

class ThreadingTCPServer(ThreadingMixIn, TCPServer):

    def __init__(self, server_address, RequestHandlerClass, relay_port=8181):
        self.lock = threading.Lock()
        self.reverse_socket = socket.socket(socket.AF_INET,
                                    socket.SOCK_STREAM)
        self.reverse_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.reverse_socket.bind(("0.0.0.0", relay_port))
        self.reverse_socket.listen(5)
        self.new_connect, self.new_connect_addr = self.reverse_socket.accept()
        TCPServer.__init__(self, server_address, RequestHandlerClass)
        self.allow_reuse_addres = True

    def get_reverse_connect(self):
        self.lock.acquire()
        while True:
            print(self.new_connect)
            self.new_connect.send(struct.pack("!4s",b'ping'))
            pattern = self.new_connect.recv(3).decode("utf-8")
            if pattern == "wan":
                ret_connect = self.new_connect
                self.new_connect, self.new_connect_addr = self.reverse_socket.accept()
                break
            self.new_connect.close()
            self.new_connect, self.new_connect_addr = self.reverse_socket.accept()
        self.lock.release()
        
        return ret_connect


class ThreadingReverseTCPServer(ThreadingMixIn, BaseServer):


    def __init__(self, server_address, RequestHandlerClass):
        BaseServer.__init__(self, server_address, RequestHandlerClass)
        self.server_address=server_address
        self.reverse_socket = socket.socket(socket.AF_INET,
                                    socket.SOCK_STREAM)
        self.reverse_socket.connect(server_address)
        self.__is_shut_down = threading.Event()
        self.__shutdown_request = False
        

    def serve_forever(self, poll_interval=0.5):
        self.__is_shut_down.clear()
        try:
            while not self.__shutdown_request:
                r, w, e = select.select([self.reverse_socket], [], [])
                self._handle_request_noblock()
                self.service_actions()
                
        finally:
            self.__shutdown_request = False
            self.__is_shut_down.set()

    def fileno(self):
        return self.reverse_socket.fileno()

    def get_request(self):
        ret_socket = self.reverse_socket
        self.reverse_socket = socket.socket(socket.AF_INET,
                                    socket.SOCK_STREAM)
        self.reverse_socket.connect(self.server_address)
        return (ret_socket, self.server_address)

    def shutdown_request(self, request):
        try:
            request.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        self.close_request(request)

    def close_request(self, request):
        request.close()



class ReverseSocksProxy(StreamRequestHandler):
    username = 'username'
    password = 'password'

    def handle(self):
        pattern = self.connection.recv(4).decode('utf-8')
        if pattern == "ping":
            print("connected")
            self.connection.send(struct.pack("!3s", b'wan'))
        else:
            self.server.close_request(self.request)
            return

        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)
        print(1)
        print(header)

        assert version == SOCKS_VERSION
        assert nmethods > 0
            
        methods = self.get_available_methods(nmethods)

        if 2 not in set(methods):
            self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0))
        else:
            self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))
            if not self.verify_credentials():
                return


        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = ord(self.connection.recv(1))
            address = self.connection.recv(domain_length)

        port = struct.unpack('!H', self.connection.recv(2))[0]

        # reply
        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                logging.info('Connected to %s %s' % (address, port))
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 1,
                                addr, port)

        except Exception as err:
            logging.error(err)
            # return connection refused error
            reply = self.generate_failed_reply(address_type, 5)

        self.connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)

        print("fi")
        self.server.close_request(self.request)




    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

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
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote):

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(1)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(1)
                if client.send(data) <= 0:
                    break
        print("end")



class SocksProxy(StreamRequestHandler):
    username = 'username'
    password = 'password'


    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address)

        self.reverse_connection = self.server.get_reverse_connect()

        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)
        self.reverse_connection.send(header)
        print(1)
        print(header)

        # socks 5
        assert version == SOCKS_VERSION
        assert nmethods > 0

        # get available methods
        methods = self.get_available_methods(nmethods)


        ret = self.reverse_connection.recv(2)
        print(2)
        print(ret)

        self.connection.sendall(ret)

        if 2 in set(methods) and not self.verify_credentials():
            return

        # request
        req = self.connection.recv(4)
        print(3)
        self.reverse_connection.send(req)
        print(req)
        version, cmd, _, address_type = struct.unpack("!BBBB", req)
        assert version == SOCKS_VERSION

        if address_type == 1:  # IPv4
            self.reverse_connection.send(self.connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length_byte = self.connection.recv(1)
            self.reverse_connection.send(domain_length_byte)
            domain_length = ord(domain_length_byte)
            self.reverse_connection.send(self.connection.recv(domain_length))

        self.reverse_connection.send(self.connection.recv(2))



        self.connection.sendall(self.reverse_connection.recv(10))

        self.exchange_loop(self.connection, self.reverse_connection)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            method_byte = self.connection.recv(1)
            self.reverse_connection.send(method_byte)
            methods.append(ord(method_byte))
        return methods

    def verify_credentials(self):
        version_byte = self.connection.recv(1)
        self.reverse_connection.send(version_byte)
        version = ord(version_byte)
        assert version == 1

        username_len_byte = self.connection.recv(1)
        self.reverse_connection.send(username_len_byte)
        username_len = ord(username_len_byte)
        username_raw = self.connection.recv(username_len)
        self.reverse_connection.send(username_raw)
        username = username_raw.decode('utf-8')

        password_len_byte = self.connection.recv(1)
        self.reverse_connection.send(password_len_byte)
        password_len = ord(password_len_byte)
        password_raw = self.connection.recv(password_len)
        self.reverse_connection.send(password_raw)
        password = password_raw.decode('utf-8')

        if username == self.username and password == self.password:
            # success, status = 0
            response=self.reverse_connection.recv(2)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        response=self.reverse_connection.recv(2)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote):

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(1)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(1)
                if client.send(data) <= 0:
                    break
        print("end")


if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "rsp:l:h:")
    except getopt.GetoptError:
        usage()
        sys.exit(1)

    is_relay = False
    is_reverse = False

    try:
        for o, a in opts:
            if o == "-r" :
                is_relay = True
            if o == "-s" :
                is_reverse = True
            if o == "-h" :
                relay_host = a
            if o == "-l" :
                proxy_port = int(a)
            if o == "-p" :
                relay_port = int(a)

        if not is_relay ^ is_reverse:
            usage()
            sys.exit(1)


        if is_relay:
            logging.info('Accepting connection from reverse' )
            server = ThreadingTCPServer(('0.0.0.0', proxy_port), SocksProxy, relay_port)
            server.serve_forever()
            logging.info('Accepting connection from hacker' )
        elif is_reverse:
            server = ThreadingReverseTCPServer((relay_host, relay_port), ReverseSocksProxy)
            server.serve_forever()
        
    except Exception as err:
        print(err)
        usage()
        sys.exit(1)
