"""Resize only the logical screen of an already-owned Xvfb display.

The gateway owns request authorization. The supervisor must serialize calls for
each display, and call initialize only after starting its new Xvfb, before any
window manager, VNC server or browser attaches. Later owner-authorized requests
select the current bounded viewport, including smaller or mixed-axis sizes.

Xvfb fixes its RandR maximum to its initial framebuffer dimensions. Start it with
``-screen 0 3840x2160x24 -noreset``, then select a smaller logical mode with initialize.
The maximum backing allocation remains in place throughout logical resizing.
The noreset option preserves modes between short-lived startup xrandr clients.
See vfbRandRInit, vfbRROutputValidateMode and vfbRRScreenSetSize in:
https://github.com/XQuartz/xorg-server/blob/master/hw/vfb/InitOutput.c
"""
import re
import subprocess
from typing import NamedTuple


MIN_WIDTH = 640
MIN_HEIGHT = 480
MAX_WIDTH = 3840
MAX_HEIGHT = 2160
INITIAL_WIDTH = 1440
INITIAL_HEIGHT = 900
XRANDR = "/usr/bin/xrandr"
COMMAND_TIMEOUT = 2
MAX_QUERY_LENGTH = 512 * 1024

_DISPLAY = re.compile(r":[0-9]{1,4}(?:\.0)?\Z")
_SCREEN = re.compile(
    r"Screen 0: minimum ([0-9]{1,5}) x ([0-9]{1,5}), current ([0-9]{1,5}) x "
    r"([0-9]{1,5}), maximum ([0-9]{1,5}) x ([0-9]{1,5})\Z"
)
# Non-verbose xrandr omits the capability list for normal-only outputs.
# Current rotation/reflection is printed outside that list: never accept it
# through a generic suffix wildcard. Physical dimensions are the final field.
_OUTPUT = re.compile(
    r"screen connected (?:primary )?([0-9]{1,5})x([0-9]{1,5})\+0\+0"
    r"(?: normal)?(?: \(normal(?: left)?(?: inverted)?(?: right)?(?: x axis)?(?: y axis)?\))?"
    r" [0-9]{1,10}mm x [0-9]{1,10}mm\Z"
)


class DisplaySizeError(RuntimeError):
    """The existing display could not be safely sized and verified."""

    def __init__(self, message, code="resize_failed"):
        super().__init__(message)
        self.code = code


class DisplayState(NamedTuple):
    width: int
    height: int
    min_width: int
    min_height: int
    max_width: int
    max_height: int
    modes: tuple[str, ...]


def bounded_viewport(width, height):
    """Reject non-integer requests and bound positive CSS-pixel dimensions."""
    if type(width) is not int or type(height) is not int or width <= 0 or height <= 0:
        raise DisplaySizeError("Viewport dimensions must be positive integers.")
    return (max(MIN_WIDTH, min(width, MAX_WIDTH)),
            max(MIN_HEIGHT, min(height, MAX_HEIGHT)))


def _environment(display, env):
    if not isinstance(display, str) or not _DISPLAY.fullmatch(display):
        raise DisplaySizeError("An explicit local Xvfb display is required.")
    if env is None:
        raise DisplaySizeError("An explicit profile environment is required.")
    result = dict(env)
    # Never mutate os.environ: more than one profile can own a display.
    result["DISPLAY"] = display
    result["LC_ALL"] = "C"
    return result


def _run(display, env, *arguments, check=lambda: None):
    check()
    code = {"--query": "resize_query_failed", "--newmode": "resize_mode_failed",
            "--addmode": "resize_attach_failed", "--output": "resize_apply_failed"}.get(
                arguments[0] if arguments else None, "resize_failed")
    try:
        result = subprocess.run(
            [XRANDR, "--display", display, *arguments],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="ascii",
            timeout=COMMAND_TIMEOUT, check=False,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        raise DisplaySizeError("The existing Xvfb display command failed.", code) from error
    check()
    if result.returncode != 0:
        raise DisplaySizeError("The existing Xvfb display rejected a RandR command.", code)
    return result.stdout


def _parse_query(output):
    if not isinstance(output, str) or len(output) > MAX_QUERY_LENGTH:
        raise DisplaySizeError("Invalid Xvfb display inventory.")
    lines = output.splitlines()
    if len(lines) < 2:
        raise DisplaySizeError("Missing Xvfb display inventory.")
    screen = _SCREEN.fullmatch(lines[0])
    active = _OUTPUT.fullmatch(lines[1])
    if screen is None or active is None:
        raise DisplaySizeError("Only one unrotated Xvfb screen at the origin is supported.")
    minimum_w, minimum_h, width, height, maximum_w, maximum_h = map(int, screen.groups())
    if not (0 < minimum_w <= width <= maximum_w <= MAX_WIDTH
            and 0 < minimum_h <= height <= maximum_h <= MAX_HEIGHT
            and (width, height) == tuple(map(int, active.groups()))):
        raise DisplaySizeError("Xvfb screen dimensions are inconsistent or outside policy bounds.")

    modes = []
    for line in lines[2:]:
        if not line.strip():
            continue
        if not line[0].isspace():
            raise DisplaySizeError("Multiple Xvfb outputs are not supported.")
        # Non-verbose xrandr output indents the existing output's mode list.
        # Mode names remain data; only locally generated names reach commands.
        modes.append(line.split()[0])
    return DisplayState(width, height, minimum_w, minimum_h,
                        maximum_w, maximum_h, tuple(modes))


def _query(display, env, check=lambda: None):
    try:
        return _parse_query(_run(display, env, "--query", check=check))
    except DisplaySizeError as error:
        error.code = "resize_query_failed"
        raise


def query(display, *, env):
    """Read the actual current dimensions; never rely on a cached viewport."""
    return _query(display, _environment(display, env))


def _apply(display, env, state, width, height, check=lambda: None):
    if not (state.min_width <= width <= state.max_width
            and state.min_height <= height <= state.max_height):
        raise DisplaySizeError(
            "The requested viewport exceeds the existing Xvfb framebuffer; "
            "its initial -screen dimensions must reserve the supported maximum."
        )
    if (state.width, state.height) == (width, height):
        return {"width": width, "height": height, "changed": False}

    mode = f"webauthn-{width}x{height}"
    if mode not in state.modes:
        # Xvfb validates dimensions only, with no physical-monitor timings.
        # Supply positive, ordered synthetic timings for this virtual output.
        horizontal = (width, width + 8, width + 16, width + 24)
        vertical = (height, height + 1, height + 2, height + 3)
        clock = horizontal[-1] * vertical[-1] * 60 / 1_000_000
        _run(display, env, "--newmode", mode, f"{clock:.6f}",
             *map(str, horizontal), *map(str, vertical), "+hsync", "+vsync", check=check)
    # Adding an already-associated mode is idempotent. A prior interrupted
    # operation may have created this global mode but not attached it yet.
    _run(display, env, "--addmode", "screen", mode, check=check)

    # --fb alone leaves the old output/CRTC mode in place; switch both together
    # so Openbox and VNC observe the same usable desktop dimensions.
    _run(display, env, "--output", "screen", "--mode", mode,
         "--fb", f"{width}x{height}", check=check)
    actual = _query(display, env, check)
    if ((actual.width, actual.height) != (width, height)
            or (actual.max_width, actual.max_height) != (state.max_width, state.max_height)):
        raise DisplaySizeError("Xvfb did not confirm the requested viewport dimensions.", "resize_unconfirmed")
    return {"width": actual.width, "height": actual.height, "changed": True}


def initialize(display, *, env, width=INITIAL_WIDTH, height=INITIAL_HEIGHT):
    """Select the initial logical size before any desktop clients attach.

    This startup-only operation requires a fresh maximum-size backing screen.
    First-view or reconnect requests use resize against the existing display.
    """
    width, height = bounded_viewport(width, height)
    environment = _environment(display, env)
    state = _query(display, environment)
    if ((state.width, state.height) != (MAX_WIDTH, MAX_HEIGHT)
            or (state.max_width, state.max_height) != (MAX_WIDTH, MAX_HEIGHT)):
        raise DisplaySizeError("Initial Xvfb sizing requires the fresh maximum-size framebuffer.")
    return _apply(display, environment, state, width, height)


def resize(display, width, height, *, env, check=lambda: None):
    """Match the bounded current viewport after owner-authorized admission.

    Failure never triggers an X server or browser restart. A timed-out or failed
    change may have taken effect; the next admitted request re-queries reality.
    """
    width, height = bounded_viewport(width, height)
    environment = _environment(display, env)
    state = _query(display, environment, check)
    return _apply(display, environment, state, width, height, check)
