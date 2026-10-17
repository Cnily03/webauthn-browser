"""One bounded JSON record with explicitly owned ancillary descriptors."""
import array
import json
import math
import os
import socket

MAX_RECORD = 8192


class ProtocolError(ValueError):
    pass


def close_rights(rights):
    for fd in rights:
        os.close(fd)


def receive(connection, *, allow_rights=False):
    data = bytearray()
    rights = []
    try:
        while b'\n' not in data:
            payload, ancillary, flags, _ = connection.recvmsg(
                MAX_RECORD + 1 - len(data), socket.CMSG_SPACE(16 * array.array('i').itemsize),
                socket.MSG_CMSG_CLOEXEC)
            unknown = False
            for level, kind, raw in ancillary:
                if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                    unknown = True
                    continue
                values = array.array('i')
                size = len(raw) - len(raw) % values.itemsize
                values.frombytes(raw[:size])
                rights.extend(values)
                unknown |= size != len(raw)
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or unknown:
                raise ProtocolError('Invalid ancillary data')
            if not payload:
                raise ProtocolError('Control connection closed')
            data.extend(payload)
            if len(data) > MAX_RECORD or len(rights) > (1 if allow_rights else 0):
                raise ProtocolError('Control record exceeded its bound')
        if not data.endswith(b'\n') or data.count(b'\n') != 1:
            raise ProtocolError('Expected exactly one control record')
        def nonfinite(_value):
            raise ProtocolError('Non-finite JSON value')
        def finite_float(raw):
            value = float(raw)
            if not math.isfinite(value):
                raise ProtocolError('Non-finite JSON value')
            return value
        def unique_fields(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ProtocolError('Duplicate control field')
                result[key] = value
            return result
        try:
            value = json.loads(data, parse_constant=nonfinite, parse_float=finite_float,
                               object_pairs_hook=unique_fields)
        except RecursionError as error:
            raise ProtocolError('Control nesting exceeded its bound') from error
        if not isinstance(value, dict):
            raise ProtocolError('Expected a control object')
        owned, rights = rights, []
        return value, owned
    finally:
        close_rights(rights)


def send(connection, value, fd=None):
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    if len(data) > MAX_RECORD:
        raise ProtocolError('Control record exceeded its bound')
    ancillary = [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))]
    # Ancillary rights are sent once. A partial stream write continues only the
    # remaining bytes; retrying sendmsg could duplicate the capability.
    sent = connection.sendmsg([data], ancillary, socket.MSG_NOSIGNAL)
    if sent <= 0:
        raise ProtocolError('Control send failed')
    if sent < len(data):
        connection.sendall(data[sent:])
