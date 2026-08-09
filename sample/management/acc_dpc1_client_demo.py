#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single TCP/UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2026 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2026 Arne Schwabe <arne@rfc2549.org>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2
#  as published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, see <https://www.gnu.org/licenses/>.
import asyncio
import base64
import json
import logging
import platform
from pprint import pprint

from sample.management.omi import OmiProtocol, OmiSendCommand

logger = logging.getLogger(__name__)

class OmiAccProtocol(OmiProtocol):
    def __init__(self, finish_future):
        super().__init__(finish_future)
        self.accmsg = ""

    def recv_notify_ACC(self, args):
        # dpc1,0,eyJkcGNfcmVx[...]
        protocol, fragment, b64msg = args.split(",", 2)
        if protocol != "dpc1":
            logging.info(f"Received unknown ACC protocol: {protocol}")
            return

        msg = base64.decodebytes(b64msg.encode())
        self.accmsg += msg.decode()

        # Message is not yet complete. Wait for more fragments.
        if fragment != "0":
            return

        self.parseDpc1(self.accmsg)
        self.accmsg = ""

    def parseDpc1(self, accmsg):
        msg = json.loads(accmsg)

        logging.error(f"Received DPC1 message: {accmsg}")

        dpc_request = msg["dpc_request"]
        ver = dpc_request["ver"]
        if ver != "1.0":
            logging.error(f"Received unknown ACC protocol version: {ver}")
            return

        client_info = dpc_request.get("client_info", False)
        antivirus = "antivirus" in dpc_request
        disk_encryption = "disk_encryption" in dpc_request

        logger.info(f"Received DPC1 request: antivirus={antivirus}, disk_encryption={disk_encryption}, client_info={client_info}")

        if client_info:
            self._sendDPC1ClientInfo()

    def _sendDPC1ClientInfo(self):
        system = platform.system()
        if system == "Darwin":
            system = "MacOS"

        response = {
            "dpc_response": {
                "ver": "1.0",
                "client_info": {
                    "os": {
                        "type": system,
                        "version": platform.release(),
                        "extra":
                            {
                                "arch": platform.machine(),
                            }
                    }
                }
            }
        }

        b64msg = base64.b64encode(json.dumps(response).encode()).decode()

        command = f"acc-msg\ndpc1\n6\n{b64msg}\nEND"
        self.queue_command(command)

async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    finish_future = loop.create_future()
    path = '/tmp/test-omi'

    transport, protocol = await loop.create_unix_connection(lambda: OmiAccProtocol(finish_future), path)

    management_version = await protocol.management_ready()
    print(f"Management interface version: {management_version}")

    await protocol.set_bytecount_interval(5)

    await finish_future


if __name__ == '__main__':
    asyncio.run(main())