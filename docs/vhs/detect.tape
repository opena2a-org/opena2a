# OpenA2A detect -- Shadow AI Discovery
# Find unmanaged AI agents and MCP servers
# Run: vhs docs/vhs/detect.tape

Output docs/vhs/detect.gif

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

# Step 1: Discover Shadow AI (25 lines)
Type "opena2a detect --verbose"
Enter
Sleep 5s

# Let users read the agent/MCP inventory
Sleep 5s

# Step 2: Audit MCP servers (19 lines)
Type "opena2a mcp"
Enter
Sleep 5s

# Let users read MCP audit results
Sleep 5s

# Step 3: Sign a server identity
Type "opena2a mcp sign filesystem"
Enter
Sleep 5s

# Final pause to read signing output
Sleep 5s
