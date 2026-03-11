# Recording OpenA2A Terminal Demos

Scripts for recording professional terminal demos with asciinema.

## Prerequisites

```bash
brew install asciinema
npm install -g opena2a-cli
```

## Scripts

| Script | Duration | Purpose |
|--------|----------|---------|
| `demo-recording.sh` | ~3 min | Full walkthrough of the security platform |
| `demo-short.sh` | ~30 sec | Social media clip (scan, protect, status) |
| `demo-setup.sh` | n/a | Creates a temp project with sample files to scan |

## Record the full demo (~3 min)

```bash
# Option A: Let the script handle setup automatically
asciinema rec demo.cast -c "bash scripts/demo-recording.sh"

# Option B: Set up the demo project first (gives you control over the working directory)
source scripts/demo-setup.sh
cd "$DEMO_DIR"
asciinema rec demo.cast -c "bash /path/to/opena2a/scripts/demo-recording.sh"
```

## Record the short demo (~30 sec)

```bash
asciinema rec demo-short.cast -c "bash scripts/demo-short.sh"
```

## Custom CLI path

If `opena2a` is not on your PATH, point to the built CLI:

```bash
export OPENA2A_CLI="node /path/to/opena2a/packages/cli/dist/index.js"
asciinema rec demo.cast -c "bash scripts/demo-recording.sh"
```

## Uploading and sharing

```bash
# Upload to asciinema.org (returns a URL)
asciinema upload demo.cast

# Or self-host the .cast file with the asciinema player
```

## Embedding on a website

Using the asciinema JS player:

```html
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/asciinema-player@3/dist/bundle/asciinema-player.css" />
<div id="demo"></div>
<script src="https://cdn.jsdelivr.net/npm/asciinema-player@3/dist/bundle/asciinema-player.min.js"></script>
<script>
  AsciinemaPlayer.create('/path/to/demo.cast', document.getElementById('demo'), {
    theme: 'monokai',
    cols: 100,
    rows: 30,
    idleTimeLimit: 2,
    speed: 1.2
  });
</script>
```

## Cleanup

The demo setup creates a temporary directory under `/tmp/opena2a-demo-*`.
It is cleaned up automatically on reboot, or you can remove it manually:

```bash
rm -rf /tmp/opena2a-demo-*
```

## Tips for a clean recording

- Use a dark terminal theme (Monokai, Dracula, or similar)
- Set terminal to 100x30 characters before recording
- Close other terminal tabs to avoid notifications
- Run the script once without recording to verify all commands work
- The `--ci` flag is passed to all commands to suppress interactive prompts
