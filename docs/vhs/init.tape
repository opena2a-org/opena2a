# OpenA2A init -- Security Posture Assessment
# Project detection, credential scan, trust score
# Run: vhs docs/vhs/init.tape

Output docs/vhs/init.gif

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

# Run security assessment (109 lines of output)
Type "opena2a init"
Enter
Sleep 10s

# Pause so viewers can read the full report
Sleep 8s
