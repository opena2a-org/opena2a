# OpenA2A demo aim -- Interactive AIM Lifecycle
# Trust score journey from 22 to 87
# Run: vhs docs/vhs/demo-aim.tape

Output docs/vhs/demo-aim.gif

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
Type "clear"
Enter
Sleep 500ms
Show

# Title pause
Sleep 1s

# Run the full AIM lifecycle demo (96 lines, 8 steps)
Type "opena2a demo aim"
Enter
Sleep 15s

# Pause so viewers can read the final summary
Sleep 8s
