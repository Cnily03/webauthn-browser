"""Isolated RandR command/model contracts; no X server or browser is started."""
import importlib.util
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("profile_display_size", ROOT / "runtime/display_size.py")
display_size = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(display_size)


def inventory(width=1440, height=900, maximum=(3840, 2160), modes=(), capabilities=True):
    suffix = " (normal left inverted right x axis y axis)" if capabilities else ""
    return (
        f"Screen 0: minimum 1 x 1, current {width} x {height}, "
        f"maximum {maximum[0]} x {maximum[1]}\n"
        f"screen connected {width}x{height}+0+0{suffix} 0mm x 0mm\n"
        f"   {width}x{height} 0.00*\n"
        + "".join(f"   {mode} 60.00\n" for mode in modes)
    )


class RandRModel:
    """An explicit simulation of the Xvfb maximum and RandR mode transitions."""

    def __init__(self, displays=None):
        self.displays = displays or {":99": [1440, 900]}
        self.maximum = {name: (3840, 2160) for name in self.displays}
        self.modes = {name: {} for name in self.displays}
        self.attached = {name: set() for name in self.displays}
        self.calls = []
        self.fail_action = None
        self.ignore_resize = False
        self.capabilities = False

    def run(self, command, **options):
        # Never invoke subprocess.run or any X command from this model.
        self.calls.append((list(command), dict(options)))
        assert command[:2] == [display_size.XRANDR, "--display"]
        display = command[2]
        assert options["env"]["DISPLAY"] == display
        action = command[3]
        if action == self.fail_action:
            self.fail_action = None
            return subprocess.CompletedProcess(command, 1, "")
        if action == "--query":
            width, height = self.displays[display]
            output = inventory(width, height, self.maximum[display], self.attached[display],
                               capabilities=self.capabilities)
            for name, (mode_width, mode_height) in self.modes[display].items():
                if name not in self.attached[display]:
                    output += (
                        f"  {name} (0x40) 100.0MHz\n"
                        f"        h: width {mode_width} start 0 end 0 total 0\n"
                        f"        v: height {mode_height} start 0 end 0 total 0\n"
                    )
            return subprocess.CompletedProcess(command, 0, output)
        if action == "--newmode":
            name = command[4]
            if name in self.modes[display]:
                return subprocess.CompletedProcess(command, 1, "")
            self.modes[display][name] = (int(command[6]), int(command[10]))
        elif action == "--addmode":
            assert command[4] == "screen"
            name = command[5]
            assert name in self.modes[display]
            self.attached[display].add(name)
        elif action == "--output":
            assert command[4] == "screen"
            assert command[5] == "--mode"
            assert command[7] == "--fb"
            name = command[6]
            assert name in self.attached[display]
            size = tuple(map(int, command[8].split("x")))
            assert self.modes[display][name] == size
            assert all(value <= maximum for value, maximum in zip(size, self.maximum[display]))
            if not self.ignore_resize:
                self.displays[display] = list(size)
        else:
            raise AssertionError(f"Unexpected simulated command: {command}")
        return subprocess.CompletedProcess(command, 0, "")


class ProfileDisplayTests(unittest.TestCase):
    def setUp(self):
        self.model = RandRModel()
        self.run_patch = patch.object(display_size.subprocess, "run", side_effect=self.model.run)
        self.run = self.run_patch.start()
        self.addCleanup(self.run_patch.stop)
        self.env = {"HOME": "/profiles/example", "DISPLAY": ":unrelated", "LC_ALL": "zh_CN.UTF-8"}

    def resize(self, width, height, display=":99"):
        return display_size.resize(display, width, height, env=self.env)

    def test_command_failures_have_fixed_stage_codes_and_keep_confirmation(self):
        for action,code in [('--query','resize_query_failed'),('--newmode','resize_mode_failed'),('--addmode','resize_attach_failed'),('--output','resize_apply_failed')]:
            self.model=RandRModel();self.model.fail_action=action
            with patch.object(display_size.subprocess,'run',side_effect=self.model.run):
                with self.assertRaises(display_size.DisplaySizeError) as caught:self.resize(1920,1080)
            self.assertEqual(caught.exception.code,code)
        self.model=RandRModel();self.model.ignore_resize=True
        with patch.object(display_size.subprocess,'run',side_effect=self.model.run):
            with self.assertRaises(display_size.DisplaySizeError) as caught:self.resize(1920,1080)
        self.assertEqual(caught.exception.code,'resize_unconfirmed')

    def test_failed_post_apply_query_preserves_actual_change_without_claiming_confirmation(self):
        def run(command, **options):
            result=self.model.run(command, **options)
            if command[3]=='--output':
                self.model.fail_action='--query'
            return result
        with patch.object(display_size.subprocess,'run',side_effect=run):
            with self.assertRaises(display_size.DisplaySizeError) as caught:self.resize(1920,1080)
        self.assertEqual(caught.exception.code,'resize_query_failed')
        self.assertEqual(self.model.displays[':99'],[1920,1080])
        self.assertEqual([call[0][3] for call in self.model.calls].count('--output'),1)

    def test_resizes_existing_display_and_verifies_actual_size(self):
        self.assertEqual(self.resize(1920, 1080), {"width": 1920, "height": 1080, "changed": True})
        self.assertEqual([call[0][3] for call in self.model.calls],
                         ["--query", "--newmode", "--addmode", "--output", "--query"])
        self.assertEqual(self.model.displays[":99"], [1920, 1080])

    def test_matching_request_only_queries_actual_size(self):
        self.assertEqual(self.resize(1440, 900), {"width": 1440, "height": 900, "changed": False})
        self.assertEqual(len(self.model.calls), 1)

    def test_smaller_request_shrinks_to_current_viewport(self):
        self.assertEqual(self.resize(800, 600), {"width": 800, "height": 600, "changed": True})
        self.assertEqual(self.model.displays[":99"], [800, 600])
        self.assertEqual(self.model.maximum[":99"], (3840, 2160))

    def test_mixed_axis_requests_match_both_dimensions(self):
        self.assertEqual(self.resize(1920, 700), {"width": 1920, "height": 700, "changed": True})
        self.assertEqual(self.resize(800, 1200), {"width": 800, "height": 1200, "changed": True})

    def test_repeated_larger_smaller_and_mixed_requests_reuse_verified_modes(self):
        sizes = [(1920, 1080), (2560, 1440), (800, 600), (1920, 700),
                 (800, 1200), (1920, 1080), (800, 600), (800, 600)]
        previous = (1440, 900)
        for width, height in sizes:
            with self.subTest(size=(width, height)):
                self.assertEqual(self.resize(width, height), {
                    "width": width, "height": height,
                    "changed": (width, height) != previous,
                })
                self.assertEqual(self.model.displays[":99"], [width, height])
                self.assertEqual(self.model.maximum[":99"], (3840, 2160))
                previous = (width, height)
        actions = [command[3] for command, _ in self.model.calls]
        self.assertEqual(actions.count("--newmode"), len(set(sizes)))
        self.assertEqual(actions.count("--output"), len(sizes) - 1)

    def test_request_is_clamped_to_supported_maximum_and_minimum(self):
        self.assertEqual(self.resize(100000, 100000), {"width": 3840, "height": 2160, "changed": True})
        self.assertEqual(self.resize(1, 1), {"width": 640, "height": 480, "changed": True})

    def test_initialization_selects_smaller_logical_mode_from_reserved_backing(self):
        self.model.displays[":99"] = [3840, 2160]
        self.assertEqual(display_size.initialize(":99", env=self.env),
                         {"width": 1440, "height": 900, "changed": True})
        self.assertEqual(self.model.maximum[":99"], (3840, 2160))
        self.assertEqual(self.resize(2560, 1440)["width"], 2560)

    def test_initialization_rejects_nonfresh_or_unreserved_screen(self):
        with self.assertRaisesRegex(display_size.DisplaySizeError, "fresh maximum-size"):
            display_size.initialize(":99", env=self.env)
        self.assertEqual(len(self.model.calls), 1)

    def test_insufficient_existing_backing_fails_without_mutation_or_restart(self):
        self.model.maximum[":99"] = (1440, 900)
        with self.assertRaisesRegex(display_size.DisplaySizeError, "initial -screen"):
            self.resize(1920, 1080)
        self.assertEqual(len(self.model.calls), 1)
        self.assertEqual(self.model.displays[":99"], [1440, 900])

    def test_explicit_environment_is_copied_without_global_display_mutation(self):
        before = dict(os.environ)
        expected = dict(self.env)
        self.resize(1920, 1080)
        self.assertEqual(self.env, expected)
        self.assertEqual(dict(os.environ), before)
        for command, options in self.model.calls:
            self.assertEqual(command[:3], ["/usr/bin/xrandr", "--display", ":99"])
            self.assertEqual(options["env"], {**expected, "DISPLAY": ":99", "LC_ALL": "C"})
            self.assertEqual(options["timeout"], display_size.COMMAND_TIMEOUT)
            self.assertEqual(options["stdin"], subprocess.DEVNULL)
            self.assertEqual(options["stderr"], subprocess.DEVNULL)
            self.assertFalse(options.get("shell", False))

    def test_profile_display_sizes_do_not_leak_between_profiles(self):
        self.model.displays[":100"] = [1024, 768]
        self.model.maximum[":100"] = (3840, 2160)
        self.model.modes[":100"] = {}
        self.model.attached[":100"] = set()
        self.resize(1920, 1080)
        self.assertEqual(self.resize(1200, 800, ":100"), {"width": 1200, "height": 800, "changed": True})
        self.assertEqual(self.model.displays[":99"], [1920, 1080])

    def test_zero_noninteger_and_boolean_requests_never_invoke_command(self):
        for size in [(0, 900), (-1, 900), (1440, 0), (True, 900),
                     (1440, False), ("1920", 1080), (1920.0, 1080), (None, 1080)]:
            with self.subTest(size=size), self.assertRaises(display_size.DisplaySizeError):
                self.resize(*size)
        self.run.assert_not_called()

    def test_remote_and_malformed_displays_are_rejected_before_command(self):
        for display in [None, "", "localhost:99", "host:99", ":99;exit", ":99\n", ":99.1", "--help"]:
            with self.subTest(display=display), self.assertRaises(display_size.DisplaySizeError):
                self.resize(1920, 1080, display)
        self.run.assert_not_called()

    def test_profile_environment_is_mandatory(self):
        with self.assertRaises(display_size.DisplaySizeError):
            display_size.resize(":99", 1920, 1080, env=None)
        self.run.assert_not_called()

    def test_local_screen_zero_suffix_is_supported(self):
        self.run.side_effect = None
        self.run.return_value = subprocess.CompletedProcess([], 0, inventory())
        self.assertEqual(display_size.query(":99.0", env=self.env).width, 1440)

    def test_command_failures_do_not_claim_resizing(self):
        for action in ("--query", "--newmode", "--addmode", "--output"):
            with self.subTest(action=action):
                model = RandRModel()
                model.fail_action = action
                self.run.side_effect = model.run
                with self.assertRaises(display_size.DisplaySizeError):
                    self.resize(1920, 1080)
                self.assertEqual(model.calls[-1][0][3], action)
                self.assertEqual(model.displays[":99"], [1440, 900])

    def test_missing_xrandr_timeout_and_decode_failure_fail_closed(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired("xrandr", 2),
                      UnicodeDecodeError("ascii", b"\xff", 0, 1, "invalid")):
            with self.subTest(error=type(error).__name__):
                self.run.side_effect = error
                with self.assertRaises(display_size.DisplaySizeError):
                    self.resize(1920, 1080)

    def test_success_status_without_actual_resize_is_not_success(self):
        self.model.ignore_resize = True
        with self.assertRaisesRegex(display_size.DisplaySizeError, "did not confirm"):
            self.resize(1920, 1080)
        self.assertEqual(self.model.calls[-1][0][3], "--query")

    def test_lost_server_state_between_commands_is_not_success(self):
        self.model.displays[":99"] = [3840, 2160]

        def reset_modes_after_client(command, **options):
            if command[3] == "--addmode" and command[5] not in self.model.modes[":99"]:
                return subprocess.CompletedProcess(command, 1, "")
            result = self.model.run(command, **options)
            # Simulate the last-client reset that Xvfb -noreset must prevent
            # while initialize runs before persistent desktop clients exist.
            self.model.modes[":99"].clear()
            self.model.attached[":99"].clear()
            self.model.displays[":99"] = [3840, 2160]
            return result

        self.run.side_effect = reset_modes_after_client
        with self.assertRaises(display_size.DisplaySizeError):
            display_size.initialize(":99", env=self.env)
        self.assertEqual(self.model.displays[":99"], [3840, 2160])

    def test_changed_server_maximum_is_not_accepted_as_verified_resizing(self):
        def change_maximum_after_apply(command, **options):
            result = self.model.run(command, **options)
            if command[3] == "--output":
                self.model.maximum[":99"] = (2560, 1440)
            return result

        self.run.side_effect = change_maximum_after_apply
        with self.assertRaisesRegex(display_size.DisplaySizeError, "did not confirm"):
            self.resize(1920, 1080)

    def test_partial_mode_creation_recovers_only_on_new_admitted_request(self):
        self.model.fail_action = "--addmode"
        with self.assertRaises(display_size.DisplaySizeError):
            self.resize(1920, 1080)
        self.assertEqual(len(self.model.calls), 3)
        self.assertEqual(self.resize(1920, 1080), {"width": 1920, "height": 1080, "changed": True})
        actions = [call[0][3] for call in self.model.calls]
        self.assertEqual(actions.count("--newmode"), 1)
        self.assertEqual(actions.count("--addmode"), 2)

    def test_canceled_owner_stops_between_commands_without_applying_screen(self):
        live=[True]
        def checked():
            if not live[0]:raise RuntimeError('owner canceled')
        def cancel_after_mode(command,**options):
            result=self.model.run(command,**options)
            if command[3]=='--newmode':live[0]=False
            return result
        self.run.side_effect=cancel_after_mode
        with self.assertRaisesRegex(RuntimeError,'owner canceled'):
            display_size.resize(':99',1920,1080,env=self.env,check=checked)
        self.assertEqual([command[3] for command,_ in self.model.calls],['--query','--newmode'])
        self.assertEqual(self.model.displays[':99'],[1440,900])

    def test_retry_after_failed_apply_reuses_existing_mode(self):
        self.model.fail_action = "--output"
        with self.assertRaises(display_size.DisplaySizeError):
            self.resize(1920, 1080)
        self.assertEqual(self.resize(1920, 1080)["width"], 1920)
        self.assertEqual(sum(command[3] == "--newmode" for command, _ in self.model.calls), 1)

    def test_new_request_queries_actual_size_after_external_change(self):
        self.resize(1920, 1080)
        self.model.displays[":99"] = [2560, 1440]
        self.assertEqual(self.resize(1920, 1080), {"width": 1920, "height": 1080, "changed": True})

    def test_accepts_normal_output_without_optional_capability_list(self):
        # xrandr omits the capabilities when rotations == RR_Rotate_0.
        for capabilities in (False, True):
            for primary in (False, True):
                output = inventory(capabilities=capabilities)
                if primary:
                    output = output.replace("screen connected ", "screen connected primary ")
                with self.subTest(capabilities=capabilities, primary=primary):
                    state = display_size._parse_query(output)
                    self.assertEqual((state.width, state.height), (1440, 900))

    def test_orientation_and_offsets_remain_rejected_without_capabilities(self):
        for capabilities in (False, True):
            output = inventory(capabilities=capabilities)
            for orientation in ("left", "right", "inverted", "normal x axis",
                                "normal y axis", "normal x and y axis"):
                with self.subTest(capabilities=capabilities, orientation=orientation):
                    with self.assertRaises(display_size.DisplaySizeError):
                        display_size._parse_query(output.replace("+0+0 ", f"+0+0 {orientation} "))
            for offset in ("+1+0", "+0+1", "-1+0", "+-1+0", "+0+-1"):
                with self.subTest(capabilities=capabilities, offset=offset):
                    with self.assertRaises(display_size.DisplaySizeError):
                        display_size._parse_query(output.replace("+0+0", offset))
            for suffix in (" left", " x axis", " unexpected", " (unknown)"):
                with self.subTest(capabilities=capabilities, suffix=suffix):
                    with self.assertRaises(display_size.DisplaySizeError):
                        display_size._parse_query(output.replace("0mm x 0mm", "0mm x 0mm" + suffix))
            with self.assertRaises(display_size.DisplaySizeError):
                display_size._parse_query(output + "second connected 640x480+0+0 0mm x 0mm\n")

    def test_rejects_ambiguous_rotated_or_mismatched_inventory(self):
        invalid = [
            "", "RandR extension missing\n", inventory().replace("Screen 0:", "Screen 1:"),
            inventory().replace("screen connected", "HDMI-1 connected"),
            inventory().replace("+0+0", "+10+0"),
            inventory().replace("+0+0 (normal", "+0+0 left (normal"),
            inventory().replace("screen connected 1440x900", "screen connected 1280x800"),
            inventory() + "second disconnected (normal)\n",
            inventory(maximum=(1280, 800)), inventory(maximum=(7680, 4320)),
            inventory().replace("current 1440", "current " + "1" * 5000),
            "x" * (display_size.MAX_QUERY_LENGTH + 1),
        ]
        for output in invalid:
            with self.subTest(output=output[:100]), self.assertRaises(display_size.DisplaySizeError):
                display_size._parse_query(output)

    def test_synthetic_timings_are_ordered_and_bounded(self):
        self.resize(3840, 2160)
        newmode = next(command for command, _ in self.model.calls if command[3] == "--newmode")
        self.assertEqual(newmode[4], "webauthn-3840x2160")
        self.assertGreater(float(newmode[5]), 0)
        horizontal = list(map(int, newmode[6:10]))
        vertical = list(map(int, newmode[10:14]))
        self.assertEqual(horizontal, sorted(set(horizontal)))
        self.assertEqual(vertical, sorted(set(vertical)))
        self.assertLess(max(horizontal + vertical), 65536)


if __name__ == "__main__":
    unittest.main()
