# mimic
Dumps local MacOS user hashes to a hashcat-compatible string.

Simply uses Objective-C instead of dscl/defaults read or other noisy binaries, to extract relevant data from ShadowHashData.

# Compilation
Open in vscode in a mac and press F5, OR

`gcc -framework Foundation -framework CoreServices -framework Collaboration main.m -o mimic`

# Usage
```
chmod +x mimic
sudo ./mimic
```

The output per user is formatted as follows:

`someLocalUser:` + $ml + `$iterations` + `$salt` + `$entropy`

To crack the hashes using hashcat:
`hashcat -m 7100 hashes.txt wordlist.txt`

Tested in Catalina, Mojave, Monterey etc.
