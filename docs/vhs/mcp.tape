# OpenA2A mcp -- MCP Server Identity
# Audit MCP configs, create Ed25519 identities, verify signatures
# Run: vhs docs/vhs/mcp.tape

Output docs/vhs/mcp.gif

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

# Step 1: Discover and audit MCP configs
Type "opena2a mcp"
Enter
Sleep 5s

# Let users read the audit
Sleep 4s

# Step 2: Sign a server identity
Type "opena2a mcp sign filesystem"
Enter
Sleep 5s

# Let users read signing output
Sleep 4s

# Step 3: Verify the signature
Type "opena2a mcp verify filesystem"
Enter
Sleep 5s

# Final pause
Sleep 4s
