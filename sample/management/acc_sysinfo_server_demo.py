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

import asyncio
# This implement a small demonstration of using the
# OpenVPN Access Server Management Interface (OMI) and an app Custom Control
# protocol (info_sample) to retrieve a number of system information from the
# client and push them to the server. To use this use on the server

# --app-custom-control info_sample
# --management /path/to/acc_sysinfo_server_demo.py unix-script

# and on the client
# --app-custom-control info_sample
# --management /path/to/acc_sysinfo_client_demo.py unix-script

import base64
import json
import logging
import random
from pprint import pprint, pformat

from omi import OMIServerProtocol, ConnectedClient
from omi_tools import run_main, start_management_protocol, ConnectData

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class SysInoConnectedClient(ConnectedClient):
   pass

class OMISysInfoServerProtocol(OMIServerProtocol):
    def __init__(self, finish_future, connect_data: ConnectData = None):
        super().__init__(finish_future, connect_data)
        self._connected_client_class = SysInoConnectedClient

    def receive_acc_client_sysinfo(self, client, protocol, acc_msg: str):
        logger.debug(f"Received sys_info message: {acc_msg!r}")
        client_info = json.loads(acc_msg)

        logger.info(f"Received sys_info response: {pformat(client_info)}")

    def client_event_ESTABLISHED(self, client, kid, env, extra):
        print(f"CLient connected: {client}")
        pprint(env)

        # TODO: track kid and don't assume we haven't done a renegotiation
        kid = 1
        asyncio.create_task(self._send_sys_info_command(client.cid, kid))

    def client_event_CONNECT(self, client, kid, env, extra):
        print(f"Authenticating client {client.cid}, {kid}")
        self.queue_command(f"client-auth-nt {client.cid} {kid}")

    async def _send_sys_info_command(self, cid, kid):
        # Give the client some time to settle its routes
        await asyncio.sleep(5)

        info = ["route", "route6", "dns-google.com", "username", "hostname", "uname"]
        # Pick 3 random infos from the client

        infos = random.choices(info, k=3)
        request = {k: True for k in infos}

        req_str = json.dumps(request).encode()

        logger.info(f"Sending sysinfo request for client {cid} with infos: {infos}")

        req_base64 = base64.encodebytes(req_str).decode()
        acc_protocol = "sys_info"

        # TODO: Implement fragmentation
        cmd = f"client-acc-msg {cid} {kid}\n{acc_protocol}\n6\n{req_base64}\nEND"

        await self.queue_command(cmd)


async def main(connect_data: ConnectData):
    transport, protocol, finish_future = await start_management_protocol(connect_data, OMISysInfoServerProtocol)

    management_version = await protocol.management_ready()
    print(f"Management interface version: {management_version}")

    await protocol.enable_log()

    await protocol.set_bytecount_interval(5)

    await finish_future


if __name__ == '__main__':
    run_main(main)
