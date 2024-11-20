# XORShellcodeLoader

A C++ program for executing obfuscated shellcode in memory. It encrypts the shellcode using XOR encryption, signs the executable with a self-signed certificate, and executes the shellcode dynamically in memory to evade detection.

## Features:
- Encrypts shellcode with XOR encryption.
- Executes shellcode in memory without writing to disk.
- Self-signs the executable using a self-signed certificate to reduce detection by antivirus tools.
- Designed for testing purposes in controlled environments.

## Usage:
1. Replace the placeholder `rawShellcode[]` with your actual shellcode.
2. Compile the program using Visual Studio or any other C++ compiler.
3. Run the generated executable to execute the shellcode.

## Disclaimer:
This program is for educational purposes only. Do not use for malicious or unauthorized activities. Always conduct testing in a safe and legal environment.
