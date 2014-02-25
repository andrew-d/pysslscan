#!/usr/bin/env python

from __future__ import print_function

import sys
import socket
from concurrent import futures

from OpenSSL import SSL
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser


def get_all_ciphers(method):
    ssl_method = getattr(SSL, method.replace('.', '_') + '_METHOD')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        context = SSL.Context(ssl_method)
        context.set_cipher_list("ALL:COMPLEMENTOFALL")
        sock = SSL.Connection(context, sock)
        ciphers = sock.get_cipher_list()
    except Exception:
        ciphers = []
    finally:
        sock.close()

    return ciphers


def make_request(sock, server_name):
    p = HttpParser()

    request = ('GET / HTTP/1.0\r\n' +
               'User-Agent: SSLScan\r\n' +
               'Host: %s\r\n\r\n' % (server_name,))
    sock.write(request)

    headers = None
    begin_done = False
    while True:
        data = sock.recv(1024)
        if not data:
            break

        recved = len(data)
        nparsed = p.execute(data, recved)
        assert nparsed == recved

        if p.is_message_begin() and not begin_done:
            begin_done = True

        if p.is_headers_complete():
            headers = p.get_headers()
            break

    return begin_done, headers


def test_cipher(server, port, method, cipher):
    ssl_method = getattr(SSL, method.replace('.', '_') + '_METHOD')
    context = SSL.Context(ssl_method)
    context.set_cipher_list(cipher)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock = SSL.Connection(context, sock)
        sock.connect((server, port))

        began, headers = make_request(sock, server)

        if began:
            print('Accepted\t' + method + '\t' + cipher)
    except SSL.Error as e:
        print('Failed\t' + method + '\t' + cipher)
        x, y = e.args[0]
    finally:
        sock.close()


def main():
    # Get the address from the user.
    server = sys.argv[1]
    port   = 443
    if ':' in server:
        server, port = server.split(':', 1)
        port = int(port)

    # TODO: get this from the user
    threads = 5

    for method in ['SSLv3', 'TLSv1']:
        supported_ciphers = get_all_ciphers(method)

        with futures.ThreadPoolExecutor(max_workers=threads) as executor:
            res = executor.map(lambda cipher: test_cipher(server, port, method, cipher),
                               supported_ciphers)
            for x in res:
                pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
