import os
import pytest
import re
import subprocess
import tempfile
import threading
import time

from pathlib import Path

OPENVPN = Path(os.environ["OPENVPN_BINARY"])
CD_PATH = Path(os.environ["WORK_DIR"])


class BasicOption:
    def __init__(self, name, *args):
        self.name = name
        self.value = " ".join(args)

    def toconfigfileitem(self):
        return f"{self.name} {self.value}\n"


class InlineOption(BasicOption):
    def __init__(self, name, *args, infile=None):
        self.name = name
        if infile is not None:
            path = Path(infile)
            if not path.is_absolute():
                path = CD_PATH / infile
            self.value = open(path).read()
        else:
            self.value = " ".join(args)

    def toconfigfileitem(self):
        return f"<{self.name}>\n{self.value.strip()}\n</{self.name}>".strip()


class OpenVPNConfig:
    DEFAULT_CONFIG_BASE = [
        BasicOption("dev", "null"),
        BasicOption("local", "localhost"),
        BasicOption("remote", "localhost"),
        BasicOption("verb", "3"),
        BasicOption("reneg-sec", "10"),
        BasicOption("ping", "1"),
        BasicOption("cd", str(CD_PATH)),
        BasicOption("ca", "sample-keys/ca.crt"),
    ]
    DEFAULT_SERVER_PORT = "16010"
    DEFAULT_CLIENT_PORT = "16011"

    def __init__(self, name="OpenVPN", options=DEFAULT_CONFIG_BASE, extra_options=[]):
        self.options = options + extra_options
        self.name = name

    def toconfigfile(self):
        c = tempfile.NamedTemporaryFile(mode="w+")
        for option in self.options:
            c.write(option.toconfigfileitem() + "\n")
            c.flush()
        return c


class ServerConfig(OpenVPNConfig):
    DEFAULT_SERVER_OPTIONS = [
        BasicOption("lport", OpenVPNConfig.DEFAULT_SERVER_PORT),
        BasicOption("rport", OpenVPNConfig.DEFAULT_CLIENT_PORT),
        BasicOption("tls-server"),
        BasicOption("dh", "none"),
        BasicOption("key", "sample-keys/server.key"),
        BasicOption("cert", "sample-keys/server.crt"),
    ]

    def __init__(self, name="Server", extra_options=[]):
        super().__init__(name=name, extra_options=self.DEFAULT_SERVER_OPTIONS)

        self.options += extra_options


class ClientConfig(OpenVPNConfig):
    DEFAULT_SERVER_OPTIONS = [
        BasicOption("lport", OpenVPNConfig.DEFAULT_CLIENT_PORT),
        BasicOption("rport", OpenVPNConfig.DEFAULT_SERVER_PORT),
        BasicOption("tls-client"),
        BasicOption("remote-cert-tls", "server"),
        BasicOption("key", "sample-keys/client.key"),
        BasicOption("cert", "sample-keys/client.crt"),
    ]

    def __init__(self, name="Client", extra_options=[]):
        super().__init__(name=name, extra_options=self.DEFAULT_SERVER_OPTIONS)

        self.options += extra_options


class RegexNotFound(Exception):
    def __init__(self, pattern, string):
        super().__init__(f'Regex "{pattern}" does not match "{string}"')


class OpenVPNProcess:
    def __init__(self, config, name=None):
        self._configfile = config.toconfigfile()
        self.name = name if name is not None else config.name
        self.full_output = ""

    def __enter__(self):
        self._p = subprocess.Popen(
            [OPENVPN, self._configfile.name], stdout=subprocess.PIPE, text=True
        )

        def append_stdout_to_string():
            for line in self._p.stdout:
                self.full_output += line

        threading.Thread(target=append_stdout_to_string).start()

        return self

    def __exit__(self, type, value, traceback):
        if self._p:
            self._p.terminate()
            self._p.wait(timeout=1)

            print(f"{self.name} log:")
            print(self.full_output)

    @property
    def returncode(self):
        return self._p.returncode

    def check_for_regex(self, pattern, flags=0):
        if re.search(pattern, self.full_output, flags=flags) is None:
            raise RegexNotFound(pattern, self.full_output)

    def wait_for_regex(self, pattern, timeout=10, re_flags=0):
        compiled_regex = re.compile(pattern, re_flags)
        end_time = time.time() + timeout
        while compiled_regex.search(self.full_output) is None:
            if time.time() > end_time:
                raise RegexNotFound(pattern, self.full_output)
            time.sleep(0.1)


def test_loopback_connection_udp():
    """Basic UDP connection setup test"""
    server = OpenVPNProcess(ServerConfig())
    client = OpenVPNProcess(ClientConfig())

    with server, client:
        server.wait_for_regex("Initialization Sequence Completed")
        client.wait_for_regex("Initialization Sequence Completed")

    assert server.returncode == 0
    assert client.returncode == 0


def test_loopback_connection_tcp():
    """Basic TCP connection setup test"""
    server = OpenVPNProcess(
        ServerConfig(extra_options=[BasicOption("proto", "tcp-server")])
    )
    client = OpenVPNProcess(
        ClientConfig(extra_options=[BasicOption("proto", "tcp-client")])
    )

    with server, client:
        server.wait_for_regex("Initialization Sequence Completed")
        client.wait_for_regex("Initialization Sequence Completed")

    assert server.returncode == 0
    assert client.returncode == 0


def test_loopback_connection_inline():
    """Basic connection setup test with inline key/cert files"""
    server = OpenVPNProcess(
        ServerConfig(
            extra_options=[
                InlineOption("ca", infile="sample-keys/ca.crt"),
                InlineOption("key", infile="sample-keys/server.key"),
                InlineOption("cert", infile="sample-keys/server.crt"),
            ]
        )
    )
    client = OpenVPNProcess(
        ClientConfig(
            extra_options=[
                InlineOption("ca", infile="sample-keys/ca.crt"),
                InlineOption("key", infile="sample-keys/client.key"),
                InlineOption("cert", infile="sample-keys/client.crt"),
            ]
        )
    )

    with server, client:
        server.wait_for_regex("Initialization Sequence Completed")
        client.wait_for_regex("Initialization Sequence Completed")

    assert server.returncode == 0
    assert client.returncode == 0


def test_loopback_connection_tls_auth():
    """Basic connection setup test with tls-auth enabled"""
    server = OpenVPNProcess(
        ServerConfig(extra_options=[BasicOption("tls-auth", "sample-keys/ta.key", "0")])
    )
    client = OpenVPNProcess(
        ClientConfig(extra_options=[BasicOption("tls-auth", "sample-keys/ta.key", "1")])
    )

    with server, client:
        server.wait_for_regex("Initialization Sequence Completed")
        client.wait_for_regex("Initialization Sequence Completed")

    server.check_for_regex(
        "Outgoing Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication"
    )
    server.check_for_regex(
        "Incoming Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication"
    )
    client.check_for_regex(
        "Outgoing Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication"
    )
    client.check_for_regex(
        "Incoming Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication"
    )

    assert server.returncode == 0
    assert client.returncode == 0


def test_loopback_connection_tls_crypt():
    """Basic connection setup test with tls-crypt enabled"""
    server = OpenVPNProcess(
        ServerConfig(extra_options=[BasicOption("tls-crypt", "sample-keys/ta.key")])
    )
    client = OpenVPNProcess(
        ClientConfig(extra_options=[BasicOption("tls-crypt", "sample-keys/ta.key")])
    )

    with server, client:
        server.wait_for_regex("Initialization Sequence Completed")
        client.wait_for_regex("Initialization Sequence Completed")

    server.check_for_regex(
        "Outgoing Control Channel Encryption: Cipher 'AES-256-CTR' initialized with 256 bit key"
    )
    server.check_for_regex(
        "Incoming Control Channel Encryption: Using 256 bit message hash 'SHA256' for HMAC authentication"
    )
    client.check_for_regex(
        "Outgoing Control Channel Encryption: Cipher 'AES-256-CTR' initialized with 256 bit key"
    )
    client.check_for_regex(
        "Incoming Control Channel Encryption: Using 256 bit message hash 'SHA256' for HMAC authentication"
    )

    assert server.returncode == 0
    assert client.returncode == 0


def test_loopback_reneg():
    """Test that OpenVPN successfully renegotiates"""
    server = OpenVPNProcess(ServerConfig(extra_options=[BasicOption("reneg-sec", "5")]))
    client = OpenVPNProcess(ClientConfig())

    with server, client:
        server.wait_for_regex("Initialization Sequence Completed")
        client.wait_for_regex("Initialization Sequence Completed")

        server.wait_for_regex(
            "TLS: soft reset.*"
            "Outgoing Data Channel: Cipher .* initialized.*"
            "Incoming Data Channel: Cipher .* initialized",
            re_flags=re.DOTALL,
        )
        # The server initiates the renegotiation, client don't log a clear
        # entry that indicates renegotiation was started, so just check that
        # the data channel was initialized at least twice.
        client.wait_for_regex(
            "Outgoing Data Channel: Cipher .* initialized.*"
            "Outgoing Data Channel: Cipher .* initialized",
            re_flags=re.DOTALL,
        )

    assert server.returncode == 0
    assert client.returncode == 0


@pytest.mark.xfail
def test_connection_xfail():
    """Example of a test that is marked as expected to fail

    TODO For discussion purposes only, remove before final version
    """
    server = OpenVPNProcess(ServerConfig())
    with server:
        server.wait_for_regex("No can do sir", timeout=1)

    assert server.returncode == 0
