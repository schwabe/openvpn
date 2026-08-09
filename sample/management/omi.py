#! /usr/bin/python3
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

# This is an example implementation in python and asyncio to drive OpenVPN's
# management interface (OMI). The permissive license allows you to use this
# code in other projects.

"""
Implementation of the OpenVPN management interface (OMI) protocol.
"""
import asyncio
import logging
import re
from asyncio import Future
from dataclasses import dataclass
from typing import override, List
from urllib import response

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

@dataclass
class OmiCommandResult:
    command: str
    result: List[str]
    error: bool
    status_text: str

@dataclass
class OmiSendCommand:
    command: str
    result: Future[OmiCommandResult]

class OmiProtocol(asyncio.Protocol):
    def __init__(self, finish_future):
        super().__init__()
        self.bytes_received = None
        self.bytes_sent = None
        self.version = -1
        self.recvBuffer = ""
        self.finish_future = finish_future
        self._can_send = asyncio.Event()
        self._can_send.clear()

        self._management_ready = asyncio.Event()
        self._management_ready.clear()
        self._response = []

        self._response_ready = asyncio.Event()
        self._response_ready.clear()

        self._send_task = asyncio.create_task(self._send_loop())
        self._send_queue = asyncio.Queue()

    @override
    def eof_received(self):
        logger.info('EOF received. Shutting down.')
        self._stop()

    @override
    def connection_lost(self, excp):
        if excp:
            logger.info(f'Connection lost ({excp}). Shutting down.')
        else:
            logger.info(f'Connection lost. Shutting down.')
        self._stop()

    def _stop(self):
        if not self.finish_future.done():
            self._send_task.cancel()
            self.finish_future.set_result(True)

    async def _send_loop(self):
        while True:
            command:OmiSendCommand = await self._send_queue.get()
            await self._can_send.wait()
            self.send_line(command.command)

            response = []
            response_complete = False

            # This is a bit brittle as it will loop forever if not getting a
            # line that starts with ERROR or SUCCESS. But this is the OMI protocol
            while not response_complete:
                await self._response_ready.wait()

                line = self._response.pop(0)
                response.append(line)

                if not self._response:
                    self._response_ready.clear()

                lastline = response[-1]
                if lastline.startswith('ERROR:'):
                    status = False
                    response_complete = True
                    _, status_text = lastline.split(":", 1)

                elif lastline.startswith('SUCCESS:'):
                    status = True
                    response_complete = True
                    _, status_text = lastline.split(":", 1)
                elif lastline == "END":
                    status = True
                    response_complete = True
                    status_text = None
                else:
                    pass
                    # Response not complete. Waiting for additional data.

            #logger.debug(f'Result received command: {response}')

            result = OmiCommandResult(command.command, response[:-1], status, status_text)

            command.result.set_result(result)
            logger.debug(f"Command done.")


    @override
    def pause_writing(self):
        self._can_send.clear()

    @override
    def resume_writing(self):
        self._can_send.set()

    @override
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        logging.info('Connection from {}'.format(peername))
        self.transport = transport
        self._can_send.set()


    @override
    def data_received(self, data):
        # OMI protocol is pure text so decode everything as UTF-8
        message = data.decode()
        self.recvBuffer += message

        parts = self.recvBuffer.split("\r\n")

        # pass complete lines to recvLine
        for part in parts[:-1]:
            logger.debug(f'Line received: {part!r}')
            self.recv_line(part)

        # keep the last incomplete line for the next call
        self.recvBuffer = parts[-1]

    def recv_line(self, line):
        if line.startswith(">"):
            self.recv_notify(line)
        else:
            self._response.append(line)
            self._response_ready.set()

    def recv_notify(self, line):
        if not ":" in line:
            logger.warning("Invalid line received: " + line)
            return

        command, args = line[1:].split(":", 1)

        # do dynamic dispatch based on command to call a handler
        if hasattr(self, f"recv_notify_{command}"):
            handler = getattr(self, f"recv_notify_{command}")
            handler(args)
            return

        logger.info("Unknown notify line received: " + line)

    def recv_notify_INFO(self, args):
            m = re.match(r"OpenVPN Management Interface Version (?P<version>\d+)", args)
            if m:
                self.version = int(m.group("version"))
                self._management_ready.set()
            else:
                logger.warning(f"Unknown INFO line received: {args}")


    def recv_notify_BYTECOUNT(self, args):
        bytes_sent, bytes_received = args.split(",",1)
        self.bytes_sent = int(bytes_sent)
        self.bytes_received = int(bytes_received)

    def recv_notify_HOLD(self, args):
        self.queue_command("hold release")

    def queue_command(self, command) -> Future[OmiCommandResult]:
        cmd = OmiSendCommand(command, Future())
        self._send_queue.put_nowait(cmd)
        return cmd.result

    async def management_ready(self) -> int:
        """
        Waits until the management interface is ready. Returns the management interface version.
        """
        await self._management_ready.wait()
        return self.version

    def send_line(self, line):
        logger.debug(f"Sending line: {line}")
        self.transport.write(f"{line}\n".encode())

    """
    Set the bytecount interval. Use 0 to disable
    """
    async def set_bytecount_interval(self,  interval:int):
        return await self.queue_command(f"bytecount {interval}")


@dataclass
class ConnectedClient:
    cid: int
    bytes_sent: int = 0
    bytes_received: int = 0

class OMIServerProtocol(OmiProtocol):
    """
    This class implement common method for the OMI when OpenVPN is running
    as a server.
    """
    def __init__(self, finish_future):
        super().__init__(finish_future)
        self._reset_pending_client_event()
        self._connected_clients = {}

    def _reset_pending_client_event(self):
        self._pending_client_event = None
        self._pending_client_event_cid = -1
        self._pending_client_event_extra_args = None
        self._client_env = {}

    def recv_notify_CLIENT(self, args:str):
        event, args = args.split(",", 1)

        if event == "ENV":
            if args == "END":
                # Client environment is finished, trigger previous client
                # event that contained an ENV
                self._trigger_client_event(self._pending_client_event, self._pending_client_event_cid, self._client_env, self._pending_client_event_extra_args)
                self._reset_pending_client_event()
            else:
                key, value = args.split("=", 1)
                self._client_env[key] = value

        elif event in ("ESTABLISHED", "DISCONNECT"):
            # This event is followed by a client environment. Wait for
            # the client evironment to be completed before triggering the event
            cid = int(args)

            self._pending_client_event = event
            self._pending_client_event_cid = cid
            if event == "ESTABLISHNED":
                self._add_client(cid)


        elif event in ("CONNECT", "REAUTH"):
            # This event is similar to other event but also carries the key-id
            cid, kid = args.split("," ,1 )
            cid, kid = int(cid), int(kid)
            self._add_client(cid)

            self._pending_client_event = event
            self._pending_client_event_cid = cid
            self._pending_client_event_extra_args = (kid, )



    def recv_notify_BYTECOUNT_CLI(self, args):
        cid, bytes_sent, bytes_received = args.split(",",2)

        client = self._connected_clients.get(int(cid))
        if client:
            client.bytes_sent = int(bytes_sent)
            client.bytes_received = int(bytes_received)

    def _trigger_client_event(self, event, cid, env, extra):
        handler_name = f"client_event_{event}"
        if hasattr(self, handler_name):
            handler = getattr(self, handler_name)
            client = self._connected_clients.get(cid, None)
            handler(client, env, extra)
        else:
            logger.debug(f"Client event {event} not handled. Method {handler_name} does not exist.")

    def _add_client(self, cid):
        if not cid in self._connected_clients:
            self._connected_clients[cid] = ConnectedClient(cid)

    def _remove_client(self, cid):
        del self._connected_clients[cid]


    async def get_client_status(self) -> OmiCommandResult:
        cmd_result = self.queue_command("status 3")
        return await cmd_result

async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    finish_future = loop.create_future()
    path = '/tmp/test-omi'

    transport, protocol = await loop.create_unix_connection(lambda: OmiProtocol(finish_future), path)

    management_version = await protocol.management_ready()
    print(f"Management interface version: {management_version}")

    await protocol.set_bytecount_interval(5)

    await finish_future


if __name__ == '__main__':
    asyncio.run(main())