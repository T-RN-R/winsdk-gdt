# winsdk-gdt
Using CastXML to parse Windows SDK headers to produce a Ghidra Data Type (GDT) archive.

## Requirements

### Windows SDK
https://developer.microsoft.com/en-us/windows/downloads/sdk-archive/
So far this has only been tested against Windows 10 SDK Version 2004 (19041). See the .NET SDK requirement below before installing this. The include path used is:

 `C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0`

### .NET SDK
Certain Windows SDK headers reference .NET SDK headers. These are an optional component of the Windows SDK install. In testing, the 4.7 .NET SDK was used from the path:

 `C:\Program Files (x86)\Windows Kits\NETFXSDK\4.7\Include`

### Visual Studio 2019 (MSVC)
I used Visual Studio 2019 Enterprise, but the headers from VS Community or the 2019 Build Tools could possibly work. The include path used was:

`C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.29.30037`

### CastXML
https://github.com/CastXML/CastXML

> CastXML is a C-family abstract syntax tree XML output tool.

This tool performs the brunt of the work. It parses the SDK headers to generate an XML representation of the functions, structs, enums, etc. which can be parsed to create Ghidra structures as part of a GDT archive.

You can build CastXML yourself, or follow the download link from the [CastXMLSuperbuild](https://github.com/CastXML/CastXMLSuperbuild) project.

### GhidraCastXML
This script generates GDT archives from CastXML output files.

https://github.com/aerosoul94/GhidraScripts

There is currently a fork with some Ghidra 10 compatibility changes which needs to be completed/merged into the main repo:

https://github.com/knifeyspoony/GhidraScripts

## Usage



```
python castxml.py --source-files 19041/win10x64_vs16_19041_c.c --extra-includes .\processhacker\phnt\include\
```
