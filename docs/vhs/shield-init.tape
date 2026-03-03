# opena2a shield init -- Unified security orchestration
# Records: full 11-step shield initialization
# THE signature demo for OpenA2A

Output docs/vhs/shield-init.gif

Require opena2a

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 700
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20
Set FontFamily "JetBrains Mono"

# Set up the demo project (hidden)
Hide
Type "bash docs/vhs/setup-lab.sh 2>/dev/null"
Enter
Sleep 1s
Type "cd /tmp/vhs-demo && clear"
Enter
Sleep 500ms
Show

# Show the project
Type "# One command to secure any AI agent project"
Enter
Sleep 1.5s

Type "opena2a shield init"
Enter
Sleep 8s

# Pause on the output so viewers can read the summary
Sleep 10s
