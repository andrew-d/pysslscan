#!/usr/bin/env python

from __future__ import print_function

__author__ = 'Andrew Dunham <andrew@du.nham.ca>'
__version__ = '0.0.1'

import sys
import socket
from concurrent import futures

from OpenSSL import SSL
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser
from cryptography.hazmat.bindings.openssl.binding import Binding as OpenSSLBinding


binding = OpenSSLBinding()
binding_ffi = binding.ffi
binding_lib = binding.lib


def get_all_ciphers(method):
    """
    Get all ciphers supported by this version of OpenSSL.
    """
    ssl_method = getattr(SSL, method.replace('.', '_') + '_METHOD')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        context = SSL.Context(ssl_method)
        context.set_cipher_list("ALL:COMPLEMENTOFALL")
        sock = SSL.Connection(context, sock)
        ciphers = sock.get_cipher_list()
    except SSL.Error:
        ciphers = []
    finally:
        sock.close()

    return ciphers


def make_request(sock, server_name):
    """
    Given an open socket, makes a simple HTTP request, parses the response, and
    returns a dictionary containing the HTTP headers that were returned by the
    server.
    """
    p = HttpParser()

    request = ('GET / HTTP/1.0\r\n' +
               'User-Agent: pySSLScan\r\n' +
               'Host: %s\r\n\r\n' % (server_name,))
    sock.write(request.encode('ascii'))

    headers = None
    while True:
        data = sock.recv(1024)
        if not data:
            break

        recved = len(data)
        nparsed = p.execute(data, recved)
        assert nparsed == recved

        if p.is_headers_complete():
            headers = p.get_headers()
            break

    return headers


def get_cipher_bits(sock):
    """
    Given a socket, gets the number of bits that the current cipher is using.
    *Very* heavily dependent on the implementation of pyOpenSSL right now. :-(
    """
    cipher = binding_lib.SSL_get_current_cipher(sock._ssl)
    if cipher == binding_ffi.NULL:
        return None

    return binding_lib.SSL_CIPHER_get_bits(cipher, binding_ffi.NULL)


def test_single_cipher(server, port, method, cipher):
    """
    Test to see if the server supports a given method/cipher combination.
    """
    ssl_method = getattr(SSL, method.replace('.', '_') + '_METHOD')
    context = SSL.Context(ssl_method)
    context.set_cipher_list(cipher)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock = SSL.Connection(context, sock)
        sock.connect((server, port))

        headers = make_request(sock, server)

        bits = get_cipher_bits(sock)
        print('Accepted\t' + method + '\t' + cipher + '\t(%d bits)' % (bits,))
    except SSL.Error as e:
        print('Failed\t' + method + '\t' + cipher)
    finally:
        sock.close()


def test_preferred_cipher(server, port, method):
    """
    Test what the server's preferred cipher is when a client will accept all
    ciphers.
    """
    ssl_method = getattr(SSL, method.replace('.', '_') + '_METHOD')
    context = SSL.Context(ssl_method)
    context.set_cipher_list("ALL:COMPLEMENTOFALL")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock = SSL.Connection(context, sock)
        sock.connect((server, port))

        headers = make_request(sock, server)

        print('Preferred cipher for %s: %s' % (method, sock.cipher()))
    except SSL.Error as e:
        pass
    finally:
        sock.close()


def validate_cert_chain(server, port):
    """
    Validate the server's certificate chain.
    """
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.set_cipher_list("ALL:COMPLEMENTOFALL")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock = SSL.Connection(context, sock)
        sock.connect((server, port))

        headers = make_request(sock, server)

        chain = sock.get_peer_cert_chain()
        for i, cert in enumerate(chain):
            print('%d: %s' % (i, cert.get_subject().commonName))
    except SSL.Error as e:
        pass
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

    ssl_version = SSL.SSLeay_version(SSL.SSLEAY_VERSION)
    if not isinstance(ssl_version, str):
        ssl_version = ssl_version.decode('ascii')
    print("pySSLScan version %s (%s)" % (
        __version__, ssl_version
    ))

    # validate_cert_chain(server, port)
    # return

    # Note that this statement will wait for all executed things to finish.
    with futures.ThreadPoolExecutor(max_workers=threads) as executor:
        results = []

        # Validate certificate chain for the server.
        results.append(executor.submit(validate_cert_chain, server, port))

        for method in ['SSLv2', 'SSLv3', 'TLSv1']:
            supported_ciphers = get_all_ciphers(method)

            # Test each individual cipher.
            for cipher in supported_ciphers:
                results.append(executor.submit(test_single_cipher, server, port, method, cipher))

            # Test for the preferred cipher suite for this method.
            results.append(executor.submit(test_preferred_cipher, server, port, method))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
