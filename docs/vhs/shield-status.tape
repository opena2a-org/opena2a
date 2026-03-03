# opena2a shield status + log -- Unified security view
# Records: shield status overview, then recent event log

Output docs/vhs/shield-status.gif

Require opena2a

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 600
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20
Set FontFamily "JetBrains Mono"

# Set up and initialize (hidden)
Hide
Type "bash docs/vhs/setup-lab.sh 2>/dev/null"
Enter
Sleep 1s
Type "cd /tmp/vhs-demo && opena2a shield init --ci --format json > /dev/null 2>&1 && clear"
Enter
Sleep 3s
Show

# Show status
Type "# View unified protection status"
Enter
Sleep 1s

Type "opena2a shield status"
Enter
Sleep 3s
Sleep 3s

# Show event log
Type "# Query the security event log"
Enter
Sleep 1s

Type "opena2a shield log --count 5"
Enter
Sleep 3s
Sleep 4s
