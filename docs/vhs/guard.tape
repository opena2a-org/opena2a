# OpenA2A guard -- Config Integrity
# SHA-256 signing and tamper detection
# Run: vhs docs/vhs/guard.tape

Output docs/vhs/guard.gif

Set Width 1200
Set Height 700
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

# Step 1: Sign config files (14 lines)
Type "opena2a guard sign"
Enter
Sleep 5s

# Let users read the signed files list
Sleep 4s

# Step 2: Verify integrity (15 lines)
Type "opena2a guard verify"
Enter
Sleep 5s

# Let users read the verification table
Sleep 4s

# Step 3: Check status (10 lines)
Type "opena2a guard status"
Enter
Sleep 4s

# Final pause
Sleep 4s
