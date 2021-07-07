# Windows SDK GDT Generator

## Usage
```
usage: generator.py [-h] --sdk-dir SDK_DIR --msvc-dir MSVC_DIR [--ghidra-dir GHIDRA_DIR] [--out OUT] [--phnt] [--mode {c,cpp}]

optional arguments:
  -h, --help            show this help message and exit
  --sdk-dir SDK_DIR     SDK Root e.g. "C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0"
  --msvc-dir MSVC_DIR   MSVC Root e.g. "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.29.30037"
  --ghidra-dir GHIDRA_DIR
                        Ghidra installation directory (defaults to $GHIDRA_HOME)
  --out OUT             Output path for generated headers. Defaults to SDK version e.g. "10.0.19041.0".
  --phnt                Include the native API includes from ProcessHacker
  --mode {c,cpp}        C or C++
  ```

## Example
```
python .\generator.py --sdk-dir "C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0" --msvc-dir "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.29.30037" --ghidra-dir "C:\Path\To\ghidra_10.0_PUBLIC" --phnt
```