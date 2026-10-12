"""Protocol/store regressions. No synthetic test bytes imply real proximity."""
import base64
import importlib.util
import json
from pathlib import Path
import unittest
import sys
import types
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('bluez_bridge', ROOT / 'runtime/bluez_bridge.py')
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)
UUID = sorted(bridge.UUIDS)[0]


def frame(data=b'public synthetic test', uuid=UUID):
    return json.dumps({'type': 'advertisement', 'uuid': uuid,
                       'data': base64.b64encode(data).decode()}).encode()


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.events = []
        self.store = bridge.AdvertisementStore(lambda *event: self.events.append(event), lambda: self.now)
        self.store.discovering = True

    def test_diagnostics_count_discovery_drops_without_payload_or_address(self):
        self.store.discovering = False
        secret = b'private BLE service bytes'
        self.store.receive(frame(secret))
        self.assertEqual(self.store.waiting, 1)
        self.assertEqual(self.store.forwarded, 0)
        self.assertEqual(self.events, [])
        self.now = 5
        with self.assertLogs(bridge.LOG, level='INFO') as logs:
            self.store.diagnostics()
        text = ' '.join(logs.output)
        self.assertIn('waiting_for_discovery=1', text)
        self.assertNotIn(secret.decode(), text)
        self.assertNotIn(base64.b64encode(secret).decode(), text)
        self.store.discovering = True
        self.store.receive(frame(secret))
        self.assertEqual(self.store.forwarded, 1)
        self.now = 10
        with self.assertLogs(bridge.LOG, level='INFO') as logs:
            self.store.diagnostics()
        self.assertIn('discovery=True forwarded=1', ' '.join(logs.output))
        self.assertIn('v2_sized=0', ' '.join(logs.output))
        self.store.receive(frame(bytes(20)))
        self.assertEqual(self.store.v2_sized, 1)

    def test_only_exact_service_data_is_forwarded(self):
        for uuid in bridge.UUIDS:
            self.assertEqual(bridge.advertisement(frame(b'\x00\xff\x01', uuid)), (uuid, b'\x00\xff\x01'))
        self.store.receive(frame())
        self.assertEqual(self.events[0][0], 'add')
        self.assertEqual(self.events[0][2][1], b'public synthetic test')

    def test_reject_unknown_fields_uuid_types_and_base64(self):
        good = json.loads(frame())
        for bad in ([], None, {'type': 'reset', 'extra': True}, {**good, 'extra': 1},
                    {**good, 'uuid': 'fff9'}, {**good, 'uuid': []},
                    {**good, 'uuid': '0000180f-0000-1000-8000-00805f9b34fb'},
                    {**good, 'data': '%%%'}, {**good, 'data': 'YQ==\n'},
                    {**good, 'data': 'YR=='}, {**good, 'data': 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                bridge.advertisement(json.dumps(bad).encode())

    def test_bounded_data_and_frames(self):
        self.assertEqual(len(bridge.advertisement(frame(b'x' * 64))[1]), 64)
        for data in (b'', b'x' * 65):
            with self.assertRaises(ValueError):
                bridge.advertisement(frame(data))
        with self.assertRaises(ValueError):
            bridge.advertisement(b' ' * (bridge.MAX_FRAME + 1))

    def test_reset_and_disconnect_clear_all_objects(self):
        self.store.receive(frame())
        self.store.receive(b'{"type":"reset"}')
        self.assertFalse(self.store.entries)
        self.assertEqual(self.events[-1][0], 'remove')
        self.store.receive(frame())
        self.store.clear()
        self.assertFalse(self.store.entries)

    def test_no_discovery_means_no_replay(self):
        self.store.discovering = False
        self.store.receive(frame())
        self.assertFalse(self.store.entries)
        self.store.discovering = True
        self.assertFalse(self.events)

    def test_duplicates_refresh_and_signal_without_creating_objects(self):
        self.store.receive(frame())
        self.now = 9
        self.store.receive(frame())
        self.assertEqual(len(self.store.entries), 1)
        self.assertEqual(self.events[-1][0], 'update')
        self.now = 10
        self.store.expire()
        self.assertEqual(len(self.store.entries), 1)
        self.now = 19
        self.store.expire()
        self.assertFalse(self.store.entries)

    def test_capacity_evicts_oldest_and_expiry_is_bounded(self):
        for index in range(bridge.MAX_DEVICES + 5):
            self.now = index / 100
            self.store.receive(frame(bytes([index])))
        self.assertEqual(len(self.store.entries), bridge.MAX_DEVICES)
        self.assertEqual(sum(event[0] == 'remove' for event in self.events), 5)
        self.now = 11
        self.store.expire()
        self.assertFalse(self.store.entries)

    def test_rate_limit_and_recovery(self):
        for _ in range(bridge.MAX_RATE):
            self.store.receive(frame())
        with self.assertRaisesRegex(ValueError, 'rate'):
            self.store.receive(frame())
        self.now = 1
        self.store.receive(frame())
        self.assertEqual(len(self.store.entries), 1)

    def test_private_bus_has_no_host_includes_or_device_access(self):
        config = (ROOT / 'runtime/dbus-system.conf').read_text()
        self.assertIn('unix:path=/data/run/dbus-system.sock', config)
        self.assertNotIn('<include', config)
        docker = (ROOT / 'Dockerfile').read_text()
        self.assertIn('python3-dbus python3-gi dbus', docker)
        source = (ROOT / 'runtime/bluez_bridge.py').read_text()
        self.assertNotIn('/dev/vhci', source)
        self.assertIn('path.chmod(0o600)', source)
        self.assertIn("do_not_queue=True", source)


class DBusInterfaceTests(unittest.TestCase):
    def setUp(self):
        # This mock verifies the exported methods, property types and signals;
        # it is deliberately not counted as a real D-Bus integration test.
        self.objects = {}
        self.signals = []
        objects, signals = self.objects, self.signals
        class Object:
            def __init__(self, bus, path):
                self.path = path
                objects[path] = self
            def remove_from_connection(self):
                objects.pop(self.path)
        class Boolean(int):
            pass
        class Error(Exception):
            def __init__(self, message, name):
                super().__init__(message)
                self.name = name
        def method(interface, **metadata):
            def decorate(fn):
                fn.dbus_interface, fn.dbus_metadata = interface, metadata
                return fn
            return decorate
        def signal(interface, **metadata):
            def decorate(fn):
                def emit(instance, *args):
                    signals.append((instance.path, interface, fn.__name__, args))
                return emit
            return decorate
        self.dbus = types.ModuleType('dbus')
        self.dbus.service = types.ModuleType('dbus.service')
        self.dbus.service.Object = Object
        self.dbus.service.method, self.dbus.service.signal = method, signal
        self.dbus.String = self.dbus.ObjectPath = str
        self.dbus.Boolean = Boolean
        self.dbus.UInt32 = int
        self.dbus.ByteArray = bytes
        self.dbus.Array = lambda values, signature: list(values)
        self.dbus.Dictionary = lambda values, signature: dict(values)
        self.dbus.exceptions = types.SimpleNamespace(DBusException=Error)
        self.bus = Mock()
        with patch.dict(sys.modules, {'dbus': self.dbus, 'dbus.service': self.dbus.service}):
            self.manager, self.adapter, self.store = bridge.create_service(self.bus, self.dbus)

    def test_object_manager_and_properties_round_trip(self):
        objects = self.manager.GetManagedObjects()
        self.assertEqual(set(objects), {bridge.ADAPTER})
        props = objects[bridge.ADAPTER][bridge.ADAPTER_IFACE]
        self.assertTrue(props['Powered'])
        self.assertFalse(props['Discovering'])
        self.assertEqual(self.adapter.GetAll(bridge.ADAPTER_IFACE), props)
        self.assertTrue(self.adapter.Get(bridge.ADAPTER_IFACE, 'Powered'))
        self.assertEqual(self.manager.GetManagedObjects.dbus_metadata['out_signature'], 'a{oa{sa{sv}}}')

    def test_scan_reports_exact_bytes_and_interfaces_then_removes(self):
        self.adapter.SetDiscoveryFilter({'UUIDs': [UUID], 'Transport': 'le', 'DuplicateData': True})
        self.adapter.StartDiscovery(sender=':1.1')
        self.store.receive(frame(b'\x00\x01\xff'))
        device_paths = set(self.manager.GetManagedObjects()) - {bridge.ADAPTER}
        self.assertEqual(len(device_paths), 1)
        device = self.objects[device_paths.pop()]
        props = device.GetAll(bridge.DEVICE_IFACE)
        self.assertEqual(props['ServiceData'], {UUID: b'\x00\x01\xff'})
        self.assertFalse(props['Connected'])
        self.assertNotIn('RSSI', props)  # Never invent distance/signal strength.
        self.assertTrue(any(event[2] == 'InterfacesAdded' for event in self.signals))
        self.store.receive(frame(b'\x00\x01\xff'))
        self.assertEqual(self.signals[-1][2], 'PropertiesChanged')
        for fn in (device.Connect, device.Pair):
            with self.assertRaisesRegex(Exception, 'Advertisement-only'):
                fn()
        self.adapter.StopDiscovery(sender=':1.1')
        self.assertEqual(set(self.manager.GetManagedObjects()), {bridge.ADAPTER})
        self.assertTrue(any(event[2] == 'InterfacesRemoved' for event in self.signals))

    def test_multiple_scanners_and_owner_disconnect(self):
        self.adapter.StartDiscovery(sender=':1.1')
        self.adapter.StartDiscovery(sender=':1.2')
        self.adapter.StopDiscovery(sender=':1.1')
        self.assertTrue(self.store.discovering)
        callback = self.bus.add_signal_receiver.call_args.args[0]
        callback(':1.2', ':1.2', '')
        self.assertFalse(self.store.discovering)

    def test_power_off_clears_sessions_and_observations(self):
        self.adapter.StartDiscovery(sender=':1.1')
        self.store.receive(frame())
        self.adapter.Set(bridge.ADAPTER_IFACE, 'Powered', self.dbus.Boolean(False))
        self.assertFalse(self.store.entries)
        with self.assertRaisesRegex(Exception, 'powered off'):
            self.adapter.StartDiscovery(sender=':1.1')
        self.adapter.Set(bridge.ADAPTER_IFACE, 'Powered', self.dbus.Boolean(True))
        self.adapter.StartDiscovery(sender=':1.1')
        self.assertTrue(self.store.discovering)

    def test_unsupported_filters_and_properties_fail(self):
        for filters in ({'Transport': 'bredr'}, {'Discoverable': True}, {'AutoConnect': True}):
            with self.assertRaises(Exception):
                self.adapter.SetDiscoveryFilter(filters)
        with self.assertRaises(Exception):
            self.adapter.Set(bridge.ADAPTER_IFACE, 'Pairable', self.dbus.Boolean(True))


if __name__ == '__main__':
    unittest.main()
