# Cross-release engine compatibility

`release_compatibility.ps1` compiles a small probe twice: once against an explicit
Git baseline and once against the current checkout. It never opens user files,
installs KASA or changes Windows file associations. Only synthetic test data is
created in a unique workspace. The workspace is retained for inspection.

Requirements: PowerShell, Git, tar, MinGW g++, and the project's dynamic OpenSSL
dependency tree. Supply the compiler and dependency paths explicitly:

```powershell
./tests/release_compatibility.ps1 -Compiler '<MinGW>/bin/g++.exe' -DependencyRoot '<vcpkg>/installed/x64-mingw-dynamic'
```

Default baseline `9ad959b` is the KASA 1.1.0 stable source commit. Change
`-Baseline` only to an inspected, trusted revision: the script compiles its code.
This probe expects the 1.1.0 engine interface, not arbitrary historical versions.

Six fixtures cover AES and legacy XOR at 0, 17 and 1,048,589 plaintext bytes.
Twenty-nine checks cover format recognition, exact decrypted bytes, preservation
of encrypted input, wrong-password rejection without output, AES in-memory
preview, and rejection of modified ciphertext. XOR coverage is for compatibility,
not a recommendation to choose XOR for new protection.

This is **engine-level evidence**, not acceptance of the distributed GUI EXE.
Before release, still check an old `.kasa` file with the candidate EXE, file
association after uninstall/reinstall, and the candidate installation/update UX.
The previously published EXE is not used to generate these fixtures; its source
commit is compiled in a separate process.
