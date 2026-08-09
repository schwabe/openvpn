#!/opt/homebrew/bin/python3
# Copyright (c) 2026 OpenVPN Inc <sales@openvpn.net>
# Copyright (c) 2026 Arne Schwabe <arne@rfc2549.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This implement a small demonstration of using the
# OpenVPN Access Server Management Interface (OMI) and an app Custom Control
# protocol (info_sample) to retrieve a number of system information from the
# client and push them to the server. To use this use on the server

# --app-custom-control info_sample
# --management /path/to/acc_sysinfo_server_demo.py unix-script

# and on the client
# --app-custom-control info_sample
# --management /path/to/acc_sysinfo_client_demo.py unix-script

# Note this is just a demonstration and not a production-ready solution.
# When modifying this code, keep the security in mind. It is easy to
# introduce a security problem when executing commands on the client.

import asyncio
import base64
import json
import logging
import os
import platform
import socket
import subprocess

from omi import OmiProtocol
from omi_tools import run_main, start_management_protocol, ConnectData
from omi_client_protocol import OMIClientProtocol

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class OmiSysInfoClientProtocol(OMIClientProtocol):
    def __init__(self, finish_future, connect_data: ConnectData):
        super().__init__(finish_future, connect_data)


    def receive_acc_sysinfo(self, accmsg):
        msg = json.loads(accmsg)

        logging.info(f"Received sys_info message: {accmsg}")

        asyncio.create_task(self.send_info_response(msg))

    async def send_info_response(self, msg):
        response = {}
        if msg.get("uname", False):
            response['uname'] = platform.uname()._asdict()

        if msg.get("username", False):
            response['username'] = os.getlogin()

        if msg.get("hostname", False):
            response['hostname'] = platform.node()

        if msg.get("dns-google.com", False):
            try:
                addrs = [x[4][0] for x in socket.getaddrinfo('google.com', 443)]
                response["dns-google.com"] = addrs

            except Exception as e:
                logging.error(f"Error resolving DNS for google.com: {e}", exc_info=True)
                response["dns-google.com"] = None

        if msg.get("route", False):
            response['route'] = await self.get_routes(False)

        if msg.get("route6", False):
            response['route6'] = await self.get_routes(True)

        msg = json.dumps(response).encode()

        await self.send_acc_msg( msg, 980)

    async def get_routes(self, v6):
        if platform.system() == 'linux':
            cmd = '/usr/sbin/ip'
            if v6:
                args = ['-6', 'route', 'show']
            else:
                args = ['-4', 'route', 'show']
        elif platform.system() == 'Darwin' or os.platform() == 'FreeBSD':
            # FreeBSD and macOS
            if os.path.exists('/usr/sbin/netstat'):
                cmd = '/usr/sbin/netstat'
            else:
                cmd = '/usr/bin/netstat'

            if v6:
                args = [ '-f', 'inet6', '-rn']
            else:

                args = [ '-f', 'inet', '-rn']
        else:
            return "Unsupported platform"

        proc = await asyncio.subprocess.create_subprocess_exec(cmd, *args, stdout=subprocess.PIPE)
        output, _ = await proc.communicate()
        return output.decode()


async def main(connect_data: ConnectData):
    transport, protocol, finish_future = await start_management_protocol(connect_data, OmiSysInfoClientProtocol)
    while True:
        await asyncio.sleep(5)
        print(".", end="", flush=True)

    management_version = await protocol.management_ready()
    print(f"Management interface version: {management_version}")

    await protocol.set_bytecount_interval(5)

    await finish_future


if __name__ == '__main__':
    run_main(main)
