# mimic
Dumps local MacOS user hashes to a hashcat-compatible string.

Simply uses Objective-C instead of dscl/defaults read or other noisy binaries, to extract relevant data from ShadowHashData.

# Download
Pre-built binaries available in [Releases](https://github.com/forefy/mimic/releases):
- `mimic-arm64` — Apple Silicon (M1/M2/M3/M4)
- `mimic-x86_64` — Intel

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

Tested in Catalina, Mojave, Monterey, Ventura, Sequoia - supports both x86_64 and arm64 (Apple Silicon).
