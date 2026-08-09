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


@dataclass
class ConnectedClient:
    """This represents a connected client instance."""
    cid: int
    bytes_sent: int = 0
    bytes_received: int = 0
    _partial_acc_msg: str = ""
    _protocol_acc_msg: str = ""


class OMIServerProtocol(OmiProtocol):
    """
    This class implement common method for the OMI when OpenVPN is running
    as a server. These are mainly helper function and functionality that
    is only available/useful for OpenVPN running as a server
    """

    # Connected client class, can be overridden by subclasses to store
    # more information about the connected client
    _connected_client_class = ConnectedClient

    def __init__(self, finish_future, connect_data: ConnectionProperties = None):
        super().__init__(finish_future, connect_data)
        self._reset_pending_client_event()
        self._connected_clients = {}

    def _reset_pending_client_event(self):
        self._pending_client_event = None
        self._pending_client_event_cid = -1
        self._pending_client_event_kid = None
        self._pending_client_event_extra_args = None
        self._client_env = {}

    def recv_notify_CLIENT(self, args: str):
        event, args = args.split(",", 1)

        if event == "ENV":
            if args == "END":
                # Client environment is finished, trigger previous client
                # event that contained an ENV
                self._trigger_client_event(self._pending_client_event, self._pending_client_event_cid,
                                           self._pending_client_event_kid, self._client_env,
                                           self._pending_client_event_extra_args)
                self._reset_pending_client_event()
            else:
                key, value = args.split("=", 1)
                self._client_env[key] = value

        elif event in ("ESTABLISHED", "DISCONNECT"):
            # This event is followed by a client environment. Wait for
            # the client evironment to be completed before triggering the event
            cid = int(args)

            self._pending_client_event = event
            self._pending_client_event_cid = int(cid)
            self._pending_client_event_kid = None
            if event == "ESTABLISHED":
                self._add_client(cid)

        elif event in ("CONNECT", "REAUTH", "CR_RESPONSE"):
            # This event is similar to other event but also carries the key-id
            cid, kid = args.split(",", 1)
            cid, kid = int(cid), int(kid)
            self._add_client(cid)

            self._pending_client_event = event
            self._pending_client_event_cid = int(cid)
            self._pending_client_event_kid = int(kid)
        elif event in ("ACC",):
            cid, kid, acc_args = args.split(",", 2)
            self._trigger_client_event(event, int(cid), int(kid), None, acc_args)
        else:
            logger.debug(f"Client event {event} not handled.")


    def client_event_ACC(self, client: ConnectedClient, kid, env, extra):
        protocol, fragment, b64msg = extra.split(",", 2)

        if client._partial_acc_msg and client._protocol_acc_msg != protocol
            logging.error(f"Recieved ACC message with protocol {protocol} before "
                          f"previous ACC message with protocol {client._protocol_acc_msg} was complete")
            client._partial_acc_msg = ""


        try:
            msg = base64.decodebytes(b64msg.encode())
            client._partial_accmsg += msg.decode()

            # Message is not yet complete. Wait for more fragments.
            if fragment != "0":
                return

            self.parse_sys_info_reply(client._partial_accmsg)
            client._partial_acc_msg = ""
            client._protocol_acc_msg = protocol

        except Exception as e:
            logger.error(f"Error parsing ACC message from client: {e}", exc_info=True)
            client._partial_acc_msg = ""
            return


        if hasattr(self, f"receive_acc_client_{protocol}"):
            handler = getattr(self, f"receive_acc_client_{protocol}")
            try:
                handler(client, protocol, client._partial_acc_msg)
            except Exception as e:
                logging.error(f"Error parsing ACC message: {e}", exc_info=True)
        else:
            logging.info(f"Received unhandled ACC protocol: {protocol}")

        client._partial_acc_msg = ""

    def recv_notify_BYTECOUNT_CLI(self, args):
        cid, bytes_sent, bytes_received = args.split(",", 2)

        client = self._connected_clients.get(int(cid))
        if client:
            client.bytes_sent = int(bytes_sent)
            client.bytes_received = int(bytes_received)

    def _trigger_client_event(self, event, cid, kid, env, extra):
        handler_name = f"client_event_{event}"
        if hasattr(self, handler_name):
            handler = getattr(self, handler_name)
            client = self._connected_clients.get(cid, None)
            handler(client, kid, env, extra)
        else:
            logger.debug(f"Client event {event} not handled. Method {handler_name} does not exist.")

    def _add_client(self, cid):
        if not cid in self._connected_clients:
            self._connected_clients[cid] = self._connected_client_class(cid = cid)

    def _remove_client(self, cid):
        del self._connected_clients[cid]

    async def get_client_status(self) -> OmiCommandResult:
        cmd_result = self.queue_command("status 3")
        return await cmd_result

