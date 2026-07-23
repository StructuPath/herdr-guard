Output assets/herdr-guard-demo.gif

Require bash
Require node

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 22
Set Width 1000
Set Height 560
Set Padding 28
Set Margin 20
Set MarginFill "#11111b"
Set BorderRadius 14
Set WindowBar "Colorful"
Set WindowBarSize 38
Set Theme "Catppuccin Mocha"
Set Framerate 30
Set TypingSpeed 42ms
Set LoopOffset 0%

Hide
Type "export PS1='guard ❯ '; herdr-guard() { ./scripts/demo.sh 'rm -r -f /'; }; clear"
Enter
Show

Sleep 1s
Type "herdr-guard test 'rm -r -f /'"
Sleep 1500ms
Enter
Sleep 8s
