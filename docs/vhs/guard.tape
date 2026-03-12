# OpenA2A guard -- Config Integrity
# SHA-256 signing and tamper detection
# Run: vhs docs/vhs/guard.tape

Output docs/vhs/guard.gif

Set Width 1200
Set Height 600
Set FontSize 20
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20
Set Framerate 30
Set PlaybackSpeed 1.0

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

# Step 1: Sign config files
Type "opena2a guard sign"
Enter
Sleep 5s

# Let users read signing output
Sleep 3s

# Step 2: Verify integrity
Type "opena2a guard verify"
Enter
Sleep 5s

# Let users read verification
Sleep 3s

# Step 3: Check status
Type "opena2a guard status"
Enter
Sleep 4s

# Final pause
Sleep 3s
