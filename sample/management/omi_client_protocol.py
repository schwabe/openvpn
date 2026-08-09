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
import base64
import logging

from omi import OmiProtocol

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class OMIClientProtocol(OmiProtocol):
    def __init__(self, finish_future, connect_data):
        super().__init__(finish_future=finish_future, connect_data=connect_data)
        self._partial_acc_msg = ""
        self._protocol_acc_msg = ""

    async def send_acc_msg(self, protocol: str, msg: bytes, fragment_length: int = 980):
        """
        Sends out an ACC to the server using the specified ACC message length
        :param protocol:
        :param msg:
        :param fragment_length:
        :return:
        """

        # calculate fragment size with base64 encoding
        fragment_length = fragment_length * 6 // 8

        commands = []
        for part_start in range(0, len(msg), fragment_length):

            msg_part = msg[part_start:part_start + fragment_length]
            b64msg = base64.encodebytes(msg_part).decode()

            flags = "6"
            if part_start + fragment_length < len(msg):
                flags = "6:F"

            commands.append(f"acc-msg\n{protocol}\n{flags}\n{b64msg}\nEND")

        for command in commands:
            self.queue_command(command)


    def recv_notify_ACC(self, args):
        protocol, fragment, b64msg = args.split(",", 2)

        if self._partial_acc_msg and self._protocol_acc_msg != protocol
            logging.error(f"Recieved ACC message with protocol {protocol} before "
                          f"previous ACC message with protocol {self._protocol_acc_msg} was complete")
            self._partial_acc_msg = ""


        try:
            msg = base64.decodebytes(b64msg.encode())
            self._partial_acc_msg += msg.decode()
            self._protocol_acc_msg = protocol
        except Exception as e:
            logging.error(f"Error parsing ACC message: {e}", exc_info=True)
            return

        # Message is not yet complete. Wait for more fragments.
        if fragment != "0":
            return

        if hasattr(self, f"receive_acc_{protocol}"):
            handler = getattr(self, f"receive_acc_{protocol}")
            try:
                handler(args)
            except Exception as e:
                logging.error(f"Error parsing ACC message: {e}", exc_info=True)
        else:
            logging.info(f"Received unhandled ACC protocol: {protocol}")

        self._partial_acc_msg = ""
        self._protocol_acc_msg = ""

