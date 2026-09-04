# opena2a init — security assessment with project detection, findings, and score
# Run: vhs docs/images/review-demo.tape
#
# Tape updated 2026-09-04. It no longer cd's into a directory that exists only on
# one maintainer's machine: the hidden setup builds docs/vhs/setup-lab.sh's demo
# project at /tmp/vhs-demo, and `init` is given that path as its operand
# (`init [directory]`, packages/cli/src/index.ts:444) rather than being run from
# inside it. docs/images/review-demo.gif is still the older recording — re-record
# it from this tape on a machine with vhs installed.

Output docs/images/review-demo.gif

Set Width 880
Set Height 620
Set FontSize 15
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms
Set Padding 15

Hide
Type "bash docs/vhs/setup-lab.sh 2>/dev/null && clear"
Enter
Sleep 2s
Show

Sleep 1s
Type "npx opena2a-cli init /tmp/vhs-demo 2>&1 | head -35"
Enter
Sleep 8s

Sleep 6s
