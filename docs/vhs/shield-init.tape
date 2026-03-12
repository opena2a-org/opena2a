# OpenA2A shield init -- Unified Security Orchestration
# Full 11-step security assessment in one command
# Run: vhs docs/vhs/shield-init.tape

Output docs/vhs/shield-init.gif

Set Width 1200
Set Height 1400
Set FontSize 20
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20
Set Framerate 30
Set PlaybackSpeed 0.5

# Hidden setup
Hide
Type "bash docs/vhs/setup-lab.sh 2>/dev/null"
Enter
Sleep 1s
Type "cd /tmp/vhs-demo && clear"
Enter
Sleep 500ms
Show

# Title pause
Sleep 1s

# Run the full shield init (76 lines of output across 11 steps)
Type "opena2a shield init"
Enter
Sleep 15s

# Pause so viewers can read the summary
Sleep 8s
