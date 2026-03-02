# opena2a protect -- Credential migration
# Records: detection, dry-run preview, migration, verification

Output docs/vhs/protect.gif

Require opena2a

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 650
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20

# Set up the demo project (hidden)
Hide
Type "bash docs/vhs/setup-lab.sh 2>/dev/null"
Enter
Sleep 1s
Type "cd /tmp/vhs-demo && clear"
Enter
Sleep 500ms
Show

# Dry run first
Type "# Preview credential migration"
Enter
Sleep 1s

Type "opena2a protect --dry-run"
Enter
Sleep 4s
Sleep 5s

# Now actually protect
Type "# Migrate credentials to environment variables"
Enter
Sleep 1s

Type "opena2a protect"
Enter
Sleep 4s
Sleep 5s

# Show the result
Type "# Verify: hardcoded keys replaced with env var references"
Enter
Sleep 500ms

Type "cat src/agent.js"
Enter
Sleep 5s
