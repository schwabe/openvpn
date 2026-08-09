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

from sample.management.omi import OmiProtocol, OmiSendCommand, OMIServerProtocol, OmiCommandResult

logger = logging.getLogger(__name__)

class OmiDPCServerProtocol(OMIServerProtocol):
    def __init__(self, finish_future):
        super().__init__(finish_future)
        self.accmsg = ""

    def recv_notify_ACC(self, args):
        # 7,3,dpc1,0,eyJkcGNfcmVx[...]
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
        pprint(msg)

        dpc_response = msg["dpc_response"]
        ver = dpc_response["ver"]
        if ver != "1.0":
            logging.error(f"Received unknown ACC protocol version: {ver}")
            return

        client_info = dpc_response.get("client_info", {})
        antivirus = "antivirus" in dpc_response
        disk_encryption = "disk_encryption" in dpc_response

        logger.info(f"Received DPC1 response: antivirus={antivirus}, disk_encryption={disk_encryption}, client_info={client_info}")


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

    def client_event_ESTABLISHED(self, client, env, extra):
        print(f"CLient connected: {client}")
        pprint(env)

    def client_event_CONNECT(self, client, env, extra):
        print(f"Authenticating client {client.cid}, {extra[0]}")
        kid = extra[0]

        iv_acc = env.get("IV_ACC")
        if not iv_acc:
            self.queue_command(f"client-auth-nt {client.cid} {kid}")

            return
        else:

            cmd = f"client-auth {client.cid} {kid}\npush \"custom-control 1280 A:6 dpc1:cck1\"\nEND"
            self.queue_command(cmd)

        self._send_dpc1_command(client.cid, kid)

    def _send_dpc1_command(self, cid, kid):
        dpc_cmd = "{\"dpc_request\":{\"ver\":\"1.0\",\"correlation_id\":\"deb4446f-2086-4af5-aa6d-ac42285ef3fe\",\"timestamp\":\"Fri Jul 17 14:08:02.395 2026\",\"client_info\":true}}"
        dpc_cmd = '{"dpc_request":{"ver":"1.0","correlation_id":"846fe236-efa0-48aa-b92e-35ae5823d2f7","timestamp":"Fri Aug 07 17:47:24.370 2026","client_info":true}}'
        dpc_cmd_base64 = base64.encodebytes(dpc_cmd.encode()).decode()
        acc_protocol = "dpc1"

        # TODO: Implement fragmentation
        cmd = f"client-acc-msg {cid} {kid}\n{acc_protocol}\n6\n{dpc_cmd_base64}\nEND"


        self.queue_command(cmd)


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    finish_future = loop.create_future()
    path = '/tmp/test-omi-server'

    transport, protocol = await loop.create_unix_connection(lambda: OmiDPCServerProtocol(finish_future), path)

    management_version = await protocol.management_ready()
    print(f"Management interface version: {management_version}")

    bs = await protocol.set_bytecount_interval(5)

    print(f"byte set result {bs}")

    while not finish_future.done():
        await asyncio.sleep(5)
        #cs:OmiCommandResult = await protocol.get_client_status()
        #print("\n".join(cs.result))



if __name__ == '__main__':
    asyncio.run(main())