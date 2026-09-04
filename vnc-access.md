# VNC access in Daytona sandboxes

Reference notes from <https://www.daytona.io/docs/en/vnc-access.md>, with the
GYMSIEGE-specific bindings noted where they apply. VNC delivers a
browser-based graphical desktop; VNC and Computer Use work together to enable
both manual and automated desktop interaction.

For how this repo actually drives it, see `sandbox_runner.py` and
[`coputer-use-agents.md`](coputer-use-agents.md); this file is the platform
reference behind those.

## Accessing VNC from the dashboard

1. Navigate to Daytona **Sandboxes**.
2. Find the target sandbox.
3. Click the options menu (⋮) next to it.
4. Select **VNC**.
5. Click **Connect**.

The browser then shows a full desktop with mouse and keyboard control.

> **Caveat.** VNC sessions stay active only while the sandbox is running. If
> the sandbox auto-stops on inactivity, start it again before reconnecting.

This matters here: an idle sandbox stopping mid-session is the same class of
problem that killed a full bake mid-`docker pull`. See `BAKE_TTL_MINUTES` and
`auto_stop_interval` in `snapshot_build.py`.

## Resolution

Set with the `VNC_RESOLUTION` environment variable **at sandbox creation**. It
cannot be changed on a running sandbox.

GYMSIEGE sets this from `common.DEFAULT_VNC_RESOLUTION`
(`VNC_RESOLUTION`, default `1280x800`), passed in `env_vars` when creating a
trial sandbox (`sandbox_runner.py:64`).

## Programmatic control

### Start

```python
result = sandbox.computer_use.start()
print("VNC processes started:", result.message)
```

```typescript
const result = await sandbox.computerUse.start();
console.log('VNC processes started:', result.message);
```

### Stop

```python
result = sandbox.computer_use.stop()
print("VNC processes stopped:", result.message)
```

```typescript
const result = await sandbox.computerUse.stop();
console.log('VNC processes stopped:', result.message);
```

### Status

```python
response = sandbox.computer_use.get_status()
print("VNC status:", response.status)
```

```typescript
const status = await sandbox.computerUse.getStatus();
console.log('VNC status:', status.status);
```

GYMSIEGE calls `computer_use.start()` once per trial
(`sandbox_runner.py:157`) before starting a screen recording. A stop failure
against a sandbox where the plugin never loaded surfaces as
`Failed to stop computer use: computer-use plugin is not loaded yet` in the
Daytona logs — benign, and distinct from a real VNC fault.

## Automating desktop interaction

With VNC running, Computer Use exposes:

- **Mouse** — click, move, drag, scroll, cursor position
- **Keyboard** — type text, press keys, hotkey combinations
- **Screenshots** — full screen, region, or compressed
- **Display** — display info and window listing

```python
sandbox.computer_use.start()
sandbox.computer_use.mouse.click(50, 50)
sandbox.computer_use.keyboard.type("https://www.daytona.io/docs/")
sandbox.computer_use.keyboard.press("enter")
screenshot = sandbox.computer_use.screenshot.take_full_screen()
```

```typescript
await sandbox.computerUse.start();
await sandbox.computerUse.mouse.click(50, 50);
await sandbox.computerUse.keyboard.type('https://www.daytona.io/docs/');
await sandbox.computerUse.keyboard.press('enter');
const screenshot = await sandbox.computerUse.screenshot.takeFullScreen();
```

GYMSIEGE's `ResearchAgent` prefers the accessibility tree over screenshots for
reading page content, falling back to screenshots only when AT-SPI yields
nothing — see [`accessibility-and-snapshots.md`](accessibility-and-snapshots.md).

## Required packages for custom images

A sandbox built from a custom image must install these explicitly; they are
present in Daytona's default images but not in a bare `debian_slim`.

**VNC and desktop environment**

- `xvfb` — X virtual framebuffer
- `xfce4` — desktop environment
- `xfce4-terminal`
- `x11vnc` — VNC server
- `novnc` — browser-based VNC client
- `dbus-x11`

**X11 libraries**

- `libx11-6`, `libxrandr2`, `libxext6`, `libxrender1`, `libxfixes3`,
  `libxss1`, `libxtst6`, `libxi6`

Relevant to this repo: `snapshot_build.py` bakes from
`Image.debian_slim("3.12")` and does **not** install any of the above, because
the CyberGym bake needs no desktop. A trial sandbox that needs
`computer_use.start()` must either restore from an image that has them or
install them first.
