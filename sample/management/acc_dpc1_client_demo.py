#!/opt/homebrew/bin/python3
#!/usr/bin/env python3
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

#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, see <https://www.gnu.org/licenses/>.
import asyncio
import base64
import json
import logging
import platform

from omi import OmiProtocol
from omi_tools import run_main, start_management_protocol, ConnectData

logger = logging.getLogger(__name__)

class OmiAccProtocol(OmiProtocol):
    def __init__(self, finish_future, connect_data:ConnectData):
        super().__init__(finish_future, connect_data)
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

        logging.error(f"Received sys_info message: {accmsg}")

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

async def main(connect_data:ConnectData):
    transport, protocol, finish_future = await start_management_protocol(connect_data, OmiAccProtocol)
    while True:
        await asyncio.sleep(1)
        print(".", end="", flush=True)

    management_version = await protocol.management_ready()
    print(f"Management interface version: {management_version}")

    await protocol.set_bytecount_interval(5)

    await finish_future


if __name__ == '__main__':
    run_main(main)