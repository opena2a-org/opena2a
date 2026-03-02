# opena2a init -- Security posture assessment
# Records: project detection, credential scan, trust score, scope drift

Output docs/vhs/init.gif

Require opena2a

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 600
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

# Show the project
Type "# Assess security posture of an AI agent project"
Enter
Sleep 1s

Type "opena2a init --verbose"
Enter
Sleep 4s

# Pause on the output so viewers can read it
Sleep 8s
