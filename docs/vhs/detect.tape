# opena2a detect -- Shadow AI Discovery
# Records: unmanaged agent detection, MCP server discovery, governance gaps
# THE enterprise demo for Shadow AI visibility

Output docs/vhs/detect.gif

Require opena2a

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 600
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

# Show the scenario
Type "# Shadow AI Discovery: what AI agents and MCP servers are running?"
Enter
Sleep 1.5s

Type "opena2a detect --verbose"
Enter
Sleep 5s

# Pause so viewers can read the findings
Sleep 8s
