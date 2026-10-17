#!/usr/bin/env python3
"""Receive-only, private BlueZ surface for Chromium's native hybrid transport.

Only service-data bytes observed by the paired local companion enter here. This
is not an HCI controller, a GATT transport, or an authenticator. Synthetic object
addresses are local identifiers, never evidence of a phone's address/proximity.
Chromium performs caBLE decryption, tunnel establishment and WebAuthn itself.
API contract: https://github.com/bluez/bluez/tree/master/doc
"""
import base64
import binascii
import hashlib
import json
import logging
import os
from pathlib import Path
import socket
import time

ADAPTER = '/org/bluez/hci0'
ADAPTER_IFACE = 'org.bluez.Adapter1'
DEVICE_IFACE = 'org.bluez.Device1'
PROPERTIES = 'org.freedesktop.DBus.Properties'
MANAGER = 'org.freedesktop.DBus.ObjectManager'
UUIDS = frozenset(('0000fff9-0000-1000-8000-00805f9b34fb',
                   '0000fde2-0000-1000-8000-00805f9b34fb'))
MAX_FRAME = 4096
MAX_DATA = 64
MAX_DEVICES = 32
EXPIRY_SECONDS = 10
MAX_RATE = 100
LOG = logging.getLogger(__name__)


def advertisement(frame):
    """Validate bytes without loading D-Bus dependencies in unit tests."""
    if len(frame) > MAX_FRAME:
        raise ValueError('Oversized frame')
    message = json.loads(frame)
    if not isinstance(message, dict):
        raise ValueError('Expected object')
    if message == {'type': 'reset'}:
        return None
    if set(message) != {'type', 'uuid', 'data'} or message['type'] != 'advertisement':
        raise ValueError('Unsupported frame')
    uuid, encoded = message['uuid'], message['data']
    if not isinstance(uuid, str) or uuid not in UUIDS or not isinstance(encoded, str):
        raise ValueError('Invalid advertisement')
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError('Invalid data') from error
    if not 1 <= len(data) <= MAX_DATA or base64.b64encode(data).decode() != encoded:
        raise ValueError('Invalid data length or encoding')
    return uuid, data


class AdvertisementStore:
    def __init__(self, emit, clock=time.monotonic):
        self.emit, self.clock = emit, clock
        self.entries = {}
        self.rate_start, self.count = clock(), 0
        self.discovering = False
        self.forwarded = self.waiting = self.v2_sized = 0
        self.last_diagnostic = clock()

    def diagnostics(self):
        now = self.clock()
        if now - self.last_diagnostic >= 5:
            self.last_diagnostic = now
            LOG.info("BLE bridge totals: discovery=%s forwarded=%d waiting_for_discovery=%d v2_sized=%d; forwarding is not phone authentication",
                     self.discovering, self.forwarded, self.waiting, self.v2_sized)

    def clear(self):
        for key in list(self.entries):
            self.entries.pop(key)
            self.emit('remove', key, None)

    def expire(self):
        now = self.clock()
        for key, (_, _, seen) in list(self.entries.items()):
            if now - seen >= EXPIRY_SECONDS:
                self.entries.pop(key)
                self.emit('remove', key, None)

    def receive(self, frame):
        now = self.clock()
        if now - self.rate_start >= 1:
            self.rate_start, self.count = now, 0
        self.count += 1
        if self.count > MAX_RATE:
            raise ValueError('Advertisement rate exceeded')
        value = advertisement(frame)
        if value is None:
            self.clear()
            return
        if not self.discovering:
            self.waiting = min(self.waiting + 1, 2**63 - 1)
            self.diagnostics()
            return
        self.expire()
        uuid, data = value
        if len(data) == 20:
            self.v2_sized = min(self.v2_sized + 1, 2**63 - 1)
        # Identifies an observation, not a hardware MAC. Never persisted.
        key = hashlib.sha256(uuid.encode() + data).hexdigest()[:32]
        if key not in self.entries and len(self.entries) >= MAX_DEVICES:
            oldest = min(self.entries, key=lambda item: self.entries[item][2])
            self.entries.pop(oldest)
            self.emit('remove', oldest, None)
        action = 'update' if key in self.entries else 'add'
        self.entries[key] = uuid, data, now
        self.emit(action, key, value)
        self.forwarded = min(self.forwarded + 1, 2**63 - 1)
        self.diagnostics()


def create_service(bus, dbus):
    """Define the real D-Bus interfaces using Debian's dbus-python."""
    import dbus.service

    def error(name, message):
        return dbus.exceptions.DBusException(message, name='org.bluez.Error.' + name)

    class Properties(dbus.service.Object):
        def __init__(self, path, interface, props):
            super().__init__(bus, path)
            self.interface, self.props = interface, props

        @dbus.service.method(PROPERTIES, in_signature='s', out_signature='a{sv}')
        def GetAll(self, interface):
            if interface != self.interface:
                return dbus.Dictionary({}, signature='sv')
            return self.props

        @dbus.service.method(PROPERTIES, in_signature='ss', out_signature='v')
        def Get(self, interface, name):
            if interface != self.interface or name not in self.props:
                raise error('InvalidArguments', 'Unknown property')
            return self.props[name]

        @dbus.service.method(PROPERTIES, in_signature='ssv', out_signature='')
        def Set(self, interface, name, value):
            if (self.interface != ADAPTER_IFACE or interface != ADAPTER_IFACE
                    or name != 'Powered' or not isinstance(value, dbus.Boolean)):
                raise error('NotSupported', 'Receive-only bridge')
            self.props[name] = dbus.Boolean(value)
            if not value:
                self.sessions.clear()
                self.props['Discovering'] = dbus.Boolean(False)
                store.discovering = False
                store.clear()
            self.PropertiesChanged(interface, {'Powered': self.props[name], 'Discovering': self.props['Discovering']}, [])

        @dbus.service.signal(PROPERTIES, signature='sa{sv}as')
        def PropertiesChanged(self, interface, changed, invalidated):
            pass

    class Adapter(Properties):
        def __init__(self):
            super().__init__(ADAPTER, ADAPTER_IFACE, {
                'Address': dbus.String('02:00:00:00:00:01'),
                'AddressType': dbus.String('random'),
                'Name': dbus.String('WebAuthn Browser BLE relay'),
                'Alias': dbus.String('WebAuthn Browser BLE relay'),
                'Class': dbus.UInt32(0), 'Powered': dbus.Boolean(True),
                'Discoverable': dbus.Boolean(False), 'Pairable': dbus.Boolean(False),
                'PairableTimeout': dbus.UInt32(0), 'DiscoverableTimeout': dbus.UInt32(0),
                'Discovering': dbus.Boolean(False), 'UUIDs': dbus.Array([], signature='s'),
                'Modalias': dbus.String(''), 'Roles': dbus.Array(['central'], signature='s'),
            })
            self.sessions = set()

        @dbus.service.method(ADAPTER_IFACE, in_signature='', out_signature='', sender_keyword='sender')
        def StartDiscovery(self, sender=None):
            if not self.props['Powered']:
                raise error('NotReady', 'Adapter is powered off')
            if sender in self.sessions:
                raise error('InProgress', 'Discovery already started')
            self.sessions.add(sender)
            LOG.info("Chromium BlueZ discovery requested")
            store.discovering = True
            self.props['Discovering'] = dbus.Boolean(True)
            self.PropertiesChanged(ADAPTER_IFACE, {'Discovering': dbus.Boolean(True)}, [])

        @dbus.service.method(ADAPTER_IFACE, in_signature='', out_signature='', sender_keyword='sender')
        def StopDiscovery(self, sender=None):
            if sender not in self.sessions:
                raise error('Failed', 'No discovery session')
            self.sessions.remove(sender)
            self.update_discovery()

        def update_discovery(self):
            was_discovering = store.discovering
            store.discovering = bool(self.sessions) and bool(self.props['Powered'])
            self.props['Discovering'] = dbus.Boolean(store.discovering)
            if was_discovering != store.discovering:
                LOG.info("Chromium BlueZ discovery state changed: active=%s", store.discovering)
            if not store.discovering:
                store.clear()
            self.PropertiesChanged(ADAPTER_IFACE, {'Discovering': self.props['Discovering']}, [])

        @dbus.service.method(ADAPTER_IFACE, in_signature='a{sv}', out_signature='')
        def SetDiscoveryFilter(self, filters):
            # Discovery is a union of caller filters in BlueZ; consumers still
            # filter the service data. This surface always limits it to caBLE.
            if set(filters) - {'UUIDs', 'Transport', 'DuplicateData', 'RSSI', 'Pathloss', 'Discoverable', 'Pattern'}:
                raise error('NotSupported', 'Unsupported filter')
            if filters.get('Transport', 'auto') not in ('auto', 'le') or filters.get('Discoverable', False):
                raise error('NotSupported', 'Only passive LE observations are supported')

        @dbus.service.method(ADAPTER_IFACE, in_signature='', out_signature='as')
        def GetDiscoveryFilters(self):
            return ['UUIDs', 'Transport', 'DuplicateData', 'RSSI', 'Pathloss', 'Pattern']

        @dbus.service.method(ADAPTER_IFACE, in_signature='o', out_signature='')
        def RemoveDevice(self, path):
            key = str(path).rsplit('/dev_', 1)[-1]
            if key not in store.entries:
                raise error('InvalidArguments', 'Unknown observation')
            store.entries.pop(key)
            emit('remove', key, None)

    class Device(Properties):
        @dbus.service.method(DEVICE_IFACE, in_signature='', out_signature='')
        def Connect(self):
            raise error('NotSupported', 'Advertisement-only bridge; no GATT transport')

        @dbus.service.method(DEVICE_IFACE, in_signature='', out_signature='')
        def Pair(self):
            raise error('NotSupported', 'Advertisement-only bridge; no pairing')

        @dbus.service.method(DEVICE_IFACE, in_signature='', out_signature='')
        def Disconnect(self):
            raise error('NotConnected', 'Advertisement-only bridge')

    class Manager(dbus.service.Object):
        @dbus.service.method(MANAGER, in_signature='', out_signature='a{oa{sa{sv}}}')
        def GetManagedObjects(self):
            objects = {ADAPTER: {ADAPTER_IFACE: adapter.props}}
            objects.update({ADAPTER + '/dev_' + key: {DEVICE_IFACE: item.props}
                            for key, item in devices.items()})
            return objects

        @dbus.service.signal(MANAGER, signature='oa{sa{sv}}')
        def InterfacesAdded(self, path, interfaces):
            pass

        @dbus.service.signal(MANAGER, signature='oas')
        def InterfacesRemoved(self, path, interfaces):
            pass

    devices = {}
    manager = Manager(bus, '/')
    adapter = Adapter()

    def emit(action, key, value):
        path = ADAPTER + '/dev_' + key
        if action == 'remove':
            device = devices.pop(key, None)
            if device is not None:
                manager.InterfacesRemoved(path, [DEVICE_IFACE])
                device.remove_from_connection()
            return
        uuid, data = value
        service_data = dbus.Dictionary({uuid: dbus.ByteArray(data)}, signature='sv')
        if action == 'update':
            devices[key].props['ServiceData'] = service_data
            devices[key].PropertiesChanged(DEVICE_IFACE, {'ServiceData': service_data}, [])
            return
        address_bytes = bytearray.fromhex(key[:12])
        address_bytes[0] = (address_bytes[0] | 2) & 0xfe
        props = {'Address': dbus.String(':'.join(f'{part:02X}' for part in address_bytes)),
                 'AddressType': dbus.String('random'), 'Adapter': dbus.ObjectPath(ADAPTER),
                 'Alias': dbus.String('Relayed caBLE observation'),
                 'Paired': dbus.Boolean(False), 'Connected': dbus.Boolean(False),
                 'Trusted': dbus.Boolean(False), 'Blocked': dbus.Boolean(False),
                 'LegacyPairing': dbus.Boolean(False), 'ServicesResolved': dbus.Boolean(False),
                 'UUIDs': dbus.Array([uuid], signature='s'), 'ServiceData': service_data}
        device = Device(path, DEVICE_IFACE, props)
        devices[key] = device
        manager.InterfacesAdded(path, {DEVICE_IFACE: props})

    store = AdvertisementStore(emit)

    def owner_changed(name, old, new):
        if old and not new and name in adapter.sessions:
            adapter.sessions.discard(name)
            adapter.update_discovery()

    bus.add_signal_receiver(owner_changed, signal_name='NameOwnerChanged', dbus_interface='org.freedesktop.DBus')
    return manager, adapter, store


def serve():
    import dbus
    import dbus.service
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib
    DBusGMainLoop(set_as_default=True)
    address = os.environ.get('DBUS_SYSTEM_BUS_ADDRESS', '')
    if not address.startswith('unix:path='):
        raise RuntimeError('A private Unix D-Bus address is required')
    bus = dbus.bus.BusConnection(address)
    name = dbus.service.BusName('org.bluez', bus, do_not_queue=True)
    manager, adapter, store = create_service(bus, dbus)
    path = Path(os.environ.get('AUTH_BROWSER_PROFILE_RUNTIME_DIR', '/data/run')) / 'ble.sock'
    if path.is_symlink():
        raise RuntimeError('Refusing symbolic link at BLE socket')
    path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    path.chmod(0o600)
    listener.listen(1)
    listener.setblocking(False)
    client, watch, pending = None, None, bytearray()

    def close_client():
        nonlocal client, watch
        if watch is not None:
            GLib.source_remove(watch)
            watch = None
        if client is not None:
            client.close()
            client = None
        pending.clear()
        store.clear()

    def receive(_fd, condition):
        nonlocal watch
        try:
            data = client.recv(MAX_FRAME + 1)
            if not data:
                raise ValueError('Disconnected')
            pending.extend(data)
            while b'\n' in pending:
                frame, _, remainder = pending.partition(b'\n')
                pending[:] = remainder
                store.receive(frame)
            if len(pending) > MAX_FRAME:
                raise ValueError('Oversized frame')
        except BlockingIOError:
            return True
        except (OSError, ValueError, UnicodeError):
            LOG.info("BLE relay stream closed or invalid frame rejected; clearing observations")
            watch = None  # Returning False removes the current source.
            close_client()
            return False
        return True

    def accept(_fd, _condition):
        nonlocal client, watch
        try:
            connection, _ = listener.accept()
        except BlockingIOError:
            return True
        # Never allow a second writer to replace an authenticated active stream.
        if client is not None:
            connection.close()
            return True
        close_client()
        client = connection
        LOG.info("Authenticated gateway BLE relay stream attached")
        client.setblocking(False)
        watch = GLib.io_add_watch(client.fileno(), GLib.IO_IN | GLib.IO_HUP | GLib.IO_ERR, receive)
        return True

    def expire():
        store.expire()
        store.diagnostics()
        return True

    GLib.io_add_watch(listener.fileno(), GLib.IO_IN, accept)
    GLib.timeout_add_seconds(1, expire)
    try:
        GLib.MainLoop().run()
    finally:
        close_client()
        listener.close()
        path.unlink(missing_ok=True)
        # Keep exported objects and ownership alive throughout the loop.
        del manager, adapter, name


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    os.umask(0o077)
    serve()
