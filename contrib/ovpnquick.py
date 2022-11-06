#! /usr/bin/python3
import argparse
import base64
import os.path
import secrets
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_pem(data: bytes, pemtype: bytes) -> bytes:
    output = b"-----BEGIN %s-----\n" % pemtype
    b = base64.encodebytes(data)
    b = b.replace(b'\n', b'')
    # Use the same 64 column splitting as OpenVPN 2.x
    for r in range(0, len(b), 64):
        output += b[r:r + 64] + b"\n"
    output += b"-----END %s-----\n" % pemtype
    return output


def generate_tls_auth():
    def gen_line(array):
        ret = ""
        for b in array:
            ret += ("%02x" % b)
        return ret

    data = secrets.token_bytes(256)

    tlsauthkey = "#\n" \
                 "# 2048 bit OpenVPN static key (Server Agent)\n" \
                 "#\n-----BEGIN OpenVPN Static key V1-----\n"
    for l in range(16):
        pos = l * 16
        tlsauthkey += gen_line(data[pos:pos + 16])
        tlsauthkey += "\n"
    tlsauthkey += "-----END OpenVPN Static key V1-----\n"
    return tlsauthkey


def generate_self_signed_certificate() -> bytes:
    # We use secp384r1 as it more modern as RSA cryptography and secp384r1
    # offer the best compatibility of eliptic curves
    key = ec.generate_private_key(
        ec.SECP384R1(),
        default_backend()
    )


def write_private_key(filename, key):
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
        ))


def add_fingerprint_to_file(filename, fingerprint, comment):
    if not os.path.exists(fingerprint):
        print(f"{filename} does not exist, creating it")
        contents = """# This file contains the SHA256 fingerprints of the certificates
                 # that the OpenVPN server will accept
                 # 
                 # Use openssl x509 -fingerprint -sha256 -in client.crt -noout
                 # to show the fingerprint of a certificate
                 <peer-fingerprint>
                 </peer-fingerprint>
                 """
        contents = contents.split("\n")
    else:
        with open(filename, "r") as fp:
            contents = fp.readlines()

        if "<peer-fingerprint>" not in contents or "<":
            print(f"Error: <peer-fingerprint> or </peer-fingerprint> not found"
                  f" in {filename}, file not in expected format")
            sys.exit(1)

        i = contents.index("</peer-fingerprint")

        contents.insert(i, f"{fingerprint}  # {comment}")

    with open(filename, "w") as fp:
        fp.write("\n".join(contents))


def parse_options():
    parser = argparse.ArgumentParser(prog='ovpn-quick',
                                     description='Quickly setup an OpenVPN setup for small deployments',
                                     epilog='Text at the bottom of help')

    parser.add_argument("--fingerprint-file", dest="fingerprints",
                        help="server side file that contains", metavar="FILE",
                        default="/etc/openvpn/server/fingerprints")

    parser.add_argument('action', metavar='command', type=str, nargs=1,
                        help="action to perform",
                        choices=['ask', 'generate-server-config', 'add-client-fingerprint'
                                                           ], default='ask')

    parser.add_argument("--server-config", dest="serverconf",
                        help="file that contains the server configuration",
                        metavar="FILE",
                        default="/etc/openvpn/server/ovpn-quick.conf")

    (options, args) = parser.parse_args()

    return options, args


def generate_server_config(options):
    serverfilename = options.
    if os.path.exists()


def main():
    options, args = parse_options()

    if not args:
        print("No command given.")

    command = args[0]

    if command == "server":
        generate_server_config(options)


if __name__ == '__main__':
    main()
