<h1 align="center">mimic</h1>

<p align="center">
  <img src="mimic-logo.svg" alt="mimic" width="200"/>
</p>

<p align="center">Dumps local MacOS user hashes to a hashcat-compatible string.</p>

<p align="center">
  <a href="https://github.com/forefy/mimic/issues/new"><img alt="Issues" title="Issues" src="https://img.shields.io/github/issues-raw/forefy/mimic"></a>
  <img alt="Code size" title="Code size" src="https://img.shields.io/github/languages/code-size/forefy/mimic">
  <img alt="Last commit" title="Last commit" src="https://img.shields.io/github/last-commit/forefy/mimic">
  <img alt="macOS" title="macOS Tahoe" src="https://img.shields.io/badge/macOS-Tahoe-black?logo=apple">
  <img alt="arch" title="Architecture" src="https://img.shields.io/badge/arch-x86__64%20%7C%20arm64-informational">
  <a href="https://twitter.com/forefy"><img alt="Forefy Twitter" title="Follow on X" src="https://img.shields.io/twitter/follow/forefy.svg?logo=twitter"></a>
</p>

<p align="center">
  <a href="https://t.me/forefy_t" title="Telegram DM">Telegram DM</a>
</p>

Simply uses Objective-C instead of dscl/defaults read or other noisy binaries, to extract relevant data from ShadowHashData.

# Download
Pre-built binaries available in [Releases](https://github.com/forefy/mimic/releases):
- `mimic-arm64` - Apple Silicon (M1/M2/M3/M4)
- `mimic-x86_64` - Intel

# Compilation
Open in vscode in a mac and press F5, OR

`clang -framework Foundation -framework AppKit -framework Collaboration main.m -o mimic`

# Usage
```
chmod +x mimic
sudo ./mimic
```

The output per user is formatted as follows:

`someLocalUser:` + $ml + `$iterations` + `$salt` + `$entropy`

To crack the hashes using hashcat:
`hashcat -m 7100 hashes.txt wordlist.txt --username`

Tested in Catalina, Mojave, Monterey, Ventura, Sequoia, Tahoe - supports both x86_64 and arm64 (Apple Silicon).
