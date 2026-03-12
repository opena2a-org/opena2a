# opena2a mcp -- MCP Server Identity
# Records: audit MCP configs, sign server identities, verify signatures

Output docs/vhs/mcp.gif

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
Type "# Audit MCP servers and create Ed25519 identities"
Enter
Sleep 1.5s

# Step 1: Discover and audit MCP configs
Type "opena2a mcp"
Enter
Sleep 4s
Sleep 3s

# Step 2: Sign a server identity
Type "opena2a mcp sign filesystem"
Enter
Sleep 4s
Sleep 3s

# Step 3: Verify the signature
Type "opena2a mcp verify filesystem"
Enter
Sleep 4s

# Pause on results
Sleep 5s
