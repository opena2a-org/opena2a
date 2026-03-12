# OpenA2A protect -- Credential Protection
# Detect hardcoded credentials, migrate to env vars
# Run: vhs docs/vhs/protect.tape

Output docs/vhs/protect.gif

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

# Step 1: Preview credential scan
Type "opena2a protect --dry-run"
Enter
Sleep 6s

# Let users read the findings
Sleep 5s

# Step 2: Run the migration
Type "opena2a protect"
Enter
Sleep 6s

# Let users read the results
Sleep 4s
