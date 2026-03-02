# opena2a guard + runtime -- Config integrity and monitoring
# Records: guard sign, guard verify, runtime init, runtime status

Output docs/vhs/guard.gif

Require opena2a

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 500
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

# Sign config files
Type "# Sign config files for tamper detection"
Enter
Sleep 1s

Type "opena2a guard sign"
Enter
Sleep 2s
Sleep 2s

# Verify
Type "opena2a guard verify"
Enter
Sleep 2s
Sleep 3s

# Initialize runtime monitoring
Type "# Set up agent runtime monitoring"
Enter
Sleep 1s

Type "opena2a runtime init"
Enter
Sleep 2s
Sleep 2s

Type "opena2a runtime status"
Enter
Sleep 2s
Sleep 3s
