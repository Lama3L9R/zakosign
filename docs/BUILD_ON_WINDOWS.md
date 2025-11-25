# Windows Build Guide

To build on windows, you must have MSVC, llvm, and nasm installed.
llvm and nasm must be present in PATH.

Then, open `Developer PowerShell for VS`, and run
```
PS> Enter-VsDevShell amd64 <\Path\To\VS>
```

To properly build boringssl
```
PS> cd boringssl
PS> cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE -DCMAKE_BUILD_TYPE=Release -G"<VS Version>" -A x64 -B build-host
PS> cd build-host
PS> msbuild  .\BoringSSL.sln -m:10 /p:Configuration=Release
```

Then, run `tools/build_win.ps1` in project root directory, and you should be good to go. 