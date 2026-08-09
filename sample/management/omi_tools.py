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
import asyncio
import os
from dataclasses import dataclass

from omi import OmiProtocol, ConnectionProperties


@dataclass
class ConnectData(ConnectionProperties):
    socket: str


def get_unix_script_environment() -> ConnectData | None:
    password = os.environ.get("MANAGEMENT_PASSWORD", None)
    socket = os.environ.get("MANAGEMENT_SOCKET", None)

    if password and socket:
        return ConnectData(password=password, socket=socket)
    else:
        return None


async def start_management_protocol(connect_data: ConnectData, protocol=OmiProtocol):
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    finish_future = loop.create_future()

    print(f"Connecting to management socket {connect_data.socket} with passwd {connect_data.password[:4]}...")
    transport, protocol = await loop.create_unix_connection(lambda: protocol(finish_future, connect_data),
                                                            connect_data.socket)

    return transport, protocol, finish_future


async def main():
    transport, protocol, finish_future = await start_management_protocol()

    management_version = await protocol.management_ready()
    await protocol.enable_log()
    print(f"Management interface version: {management_version}")

    await protocol.set_bytecount_interval(5)

    await finish_future


def run_main(main_func, connect_parameters: ConnectData = None):
    """
    Example function to run a main function to be either using the
    environment variable for the unix-script or to use. If the unix-script
    environment are detected, the function will fork and run the main_func
    with the ConnectData from the environment. If the environment variables
    are not available, it will not fork will fall back to the connect_parameters
    if present.
    :param connect_parameters:  fallback connect parameters if unix-script is not available
    :param main_func:           The function to call.
    :return:
    """
    unix_script_parameters = get_unix_script_environment()
    if unix_script_parameters:
        asyncio.run(main_func(unix_script_parameters))
    elif connect_parameters:
        asyncio.run(main_func(connect_parameters))
    else:
        print(f"Must be called via unix-script")


if __name__ == '__main__':
    run_main(main)
