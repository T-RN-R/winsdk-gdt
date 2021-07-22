import argparse
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess

import castxml
import constants
import msvc

PROJECT_NAME = 'winsdk-gdt'
SCRIPT_ROOT = pathlib.Path(__name__).parent.absolute()
SDK_ROOT = SCRIPT_ROOT / 'sdk'
MD_ROOT = SCRIPT_ROOT / "win32metadata/generation/scraper/Partitions"
ENUMS_JSON_PATH = SCRIPT_ROOT / "win32metadata/generation/scraper/enums.json"
PHNT_ROOT = SCRIPT_ROOT / "processhacker/phnt/include"
BUILD_ROOT = SCRIPT_ROOT / "build"
CPP_MODE = 'cpp'
C_MODE = 'c'
CPP_SDK_DIR = 'sdk_cpp'
C_SDK_DIR = 'sdk_c'

BASE_C_DEFS = """\
// Base Requirements:
#pragma warning(disable: 4117 4005)
#define _AMD64_
#define DIRECTINPUT_VERSION 0x800
#include <sdkddkver.h>
#include <stdbool.h>
"""

BASE_CPP_DEFS = """\
// Base Requirements:
#pragma warning(disable: 4117 4005)
#define _AMD64_
#define DIRECTINPUT_VERSION 0x800
#define __STDCPP_DEFAULT_NEW_ALIGNMENT__ 16ull
#define _MSC_EXTENSIONS 1
#define _WCHAR_T_DEFINED
#define _NATIVE_WCHAR_T_DEFINED
#define __cplusplus 201711
#define _MSVC_LANG 201402
#define _MSC_VER 1929
typedef int _Bool;
#include <sdkddkver.h>
"""

PHNT_CPP = """
#include "_basedefs.hpp"
#define PHNT_VERSION 111
#include <phnt_windows.h>
#include <phnt.h>
"""

PHNT_C = """
#include "_basedefs.h"
#define PHNT_VERSION 111
#include <phnt_windows.h>
#include <phnt.h>
"""

PHNT_TRAVERSE = [
    "ntpsapi.h",
    "ntregapi.h",
    "ntrtl.h",
    "ntsam.h",
    "ntseapi.h",
    "ntsmss.h",
    "nttmapi.h",
    "nttp.h",
    "ntwow64.h",
    "ntxcapi.h",
    "ntzwapi.h",
    "phnt.h",
    "phnt_ntdef.h",
    "phnt_windows.h",
    "subprocesstag.h",
    "winsta.h",
    "ntd3dkmt.h",
    "ntdbg.h",
    "ntexapi.h",
    "ntgdi.h",
    "ntioapi.h",
    "ntkeapi.h",
    "ntldr.h",
    "ntlpcapi.h",
    "ntmisc.h",
    "ntmmapi.h",
    "ntnls.h",
    "ntobapi.h",
    "ntpebteb.h",
    "ntpfapi.h",
    "ntpnpapi.h",
    "ntpoapi.h"
]

class GeneratorException(Exception):
    pass

def generate_header(folder: pathlib.Path):
    namespace = folder.stem
    cpp_file = folder / "main.cpp"
    if not cpp_file.exists():
        raise GeneratorException(f"Missing include data for {namespace} ({folder})")
    # print(f"Processing include data for {namespace}")
    include_data = cpp_file.read_text()
    include_data = re.sub('#include "intrinfix.h"', '', include_data)
    include_data = re.sub('"windows.fixed.h"', '<windows.h>', include_data)
    return include_data

def generate_traverse(folder: pathlib.Path):
    namespace = folder.stem
    settings_file = folder / "settings.rsp"
    if not settings_file.exists():
        raise GeneratorException(f"Missing settings data for {namespace} ({folder})")
    settings_data = settings_file.read_text()
    # Scrape header names from the settings file, they are only included in the traverse list
    traverse_list = re.findall('/((?:[^/]+?)(?=\.h\s)\.h)\s', settings_data)
    return traverse_list
    
def parse_win32metadata(out_path: pathlib.Path, mode: str):
    """Parse each namespace in the partitions folder"""

    # Write our base defs header
    if mode == CPP_MODE:
        base_defs = out_path / '_basedefs.hpp'
        base_defs.write_text(BASE_CPP_DEFS)
        suffix = 'cpp'
        fixup = fixup_cpp_header
    else:
        base_defs = out_path / '_basedefs.h'
        base_defs.write_text(BASE_C_DEFS)
        suffix = 'c'
        fixup = fixup_c_header
    
    for child in MD_ROOT.glob("*"):
        if not child.is_dir():
            continue
        # NOTE: This isn't a C++ namespace, it's just the "API"
        namespace = child.stem

        # This is the source file data (main.cpp in the namespace dir)
        header_data = generate_header(child)

        # This is the list of headers that belong to the namespace (from settings.rsp in the namespace dir)
        traverse_list = generate_traverse(child)

        # Write out the data to the 'sdk' directories (within the output directory)
        header_name = f"{namespace}.{suffix}"
        traverse_name = f"{namespace}.traverse.json"
        
        # Some of the SDK headers are NOT C-compatible.. invoke fixup to omit them
        header_path = out_path / header_name
        header_path.write_text(fixup(namespace, header_data))

        traverse_path = out_path / traverse_name
        traverse_path.write_text(json.dumps(traverse_list))


def fixup_c_header(namespace, data):
    # Remove headers we know to be C++ only
    for header in CPP_ONLY:
        pattern = f'(#include (?:<|\"){header}(?:>|\"))'        
        data = re.sub(pattern, '//\\1 (C++ only)', data, flags=re.IGNORECASE)

    # Prepend our base definitions header
    data = '#include "_basedefs.h"\n\n'  + data

    # Handle special cases
    data = NS_HANDLERS.get(namespace, null_ns_handler)(data)

    # Mark where the parser should begin
    return data

def fixup_cpp_header(namespace, data):
    data = '#include "_basedefs.hpp"\n\n'  + data
    return data

def parse_sdk(inc_dir: pathlib.Path, sdk_dir: pathlib.Path, msvc_dir: pathlib.Path, mode, extra_includes):
    
    # Feed the SDK files into castxml
    if is_cpp:= mode == CPP_MODE:
        src_files = list(inc_dir.glob('*.cpp'))
    else:
        src_files = list(inc_dir.glob('*.c'))

    castxml.invoke_castxml(
        src_files=src_files,
        mode=castxml.Mode.USER,
        is_cpp=is_cpp,
        sdk_dir=sdk_dir,
        dotnet_sdk_dir=None,
        msvc_dir=msvc_dir,
        extra_includes=extra_includes,
        skip_existing=True
    )

    # We want to output the list of headers that contain types for this namespace, as defined by
    # the --traverse list in the partition folder from win32metadata

    # If C++, we also want to dump class layouts/vftable contents
    if is_cpp:
        if BUILD_ROOT.exists():
            shutil.rmtree(BUILD_ROOT)
        BUILD_ROOT.mkdir()
        curdir = os.curdir
        try:
            os.chdir(BUILD_ROOT)
            msvc_includes = [
                sdk_dir / 'ucrt',
                sdk_dir / 'um',
                sdk_dir / 'shared',
                sdk_dir / 'winrt',
                sdk_dir / 'cppwinrt',
            ]
            msvc.dump_class_layouts(msvc_dir=msvc_dir, src_files=src_files, inc_paths=msvc_includes)
        finally:
            os.chdir(curdir)

def create_gdt(data_dir:pathlib.Path, ghidra_dir: pathlib.Path):
    """
        Run a ghidra script without a program:
        analyzeHeadless /Users/user/ghidra/projects MyProject -preScript HelloWorldScript.java -scriptPath /my/ghidra_scripts
    Args:
        data_dir (pathlib.Path): Directory containing sdk files
        ghidra_dir (pathlib.Path): [description]
    """

    # Ghidra 10.0.1 needs you to be in the support directory..?
    current_dir = os.getcwd()
    support_dir = ghidra_dir / 'support'
    print(support_dir)
    os.chdir(str(support_dir.absolute()))
    print(os.getcwd())

    try:
        # Jython 2.7
        headless_script = support_dir / 'analyzeHeadless.bat'
        # ghidra_args = shlex.split(
        #     f"{headless_script.as_posix()} {BUILD_ROOT.as_posix()} tmp -preScript {GDT_SCRIPT.as_posix()} {data_dir.as_posix()} -scriptPath {SCRIPT_ROOT.as_posix()}"
        # )
        ghidra_args = shlex.split(
            f"{headless_script.as_posix()} {BUILD_ROOT.as_posix()} tmp -scriptPath {SCRIPT_ROOT.as_posix()} -preScript gdt.py {data_dir.as_posix()}"
        )
        print(ghidra_args)
        ghidra_proc = subprocess.Popen(ghidra_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in ghidra_proc.stdout:
            print(line.decode('utf-8').strip())
    finally:
        os.chdir(current_dir)

def parse_constants(data_dir:pathlib.Path, sdk_dir: pathlib.Path):
    sdk_dirs = [
        sdk_dir / 'ucrt',
        sdk_dir / 'um',
        sdk_dir / 'shared',
        sdk_dir / 'winrt',
        sdk_dir / 'cppwinrt',
    ]
    constants.EnumParser(ENUMS_JSON_PATH, sdk_dirs, data_dir)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdk-dir', help=r'SDK Root e.g. "C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0"', required=True)
    parser.add_argument('--msvc-dir', help=r'MSVC Root e.g. "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.29.30037"', required=True)
    parser.add_argument('--ghidra-dir', help=r'Ghidra installation directory (defaults to $GHIDRA_HOME)', required=False, default=None)
    parser.add_argument('--out', help=r'Output path for generated headers. Defaults to SDK version e.g. "10.0.19041.0".', required=False, default=None)
    parser.add_argument('--phnt', help=r'Include the native API includes from ProcessHacker', action="store_true", required=False, default=False)
    parser.add_argument('--mode', help=r'C or C++', choices=[C_MODE, CPP_MODE], default=CPP_MODE, required=False)
    args = parser.parse_args()

    # Check Ghidra
    if not (ghidra_dir := args.ghidra_dir):
        if not (ghidra_dir := os.getenv('GHIDRA_HOME')):
            raise GeneratorException(f"No Ghidra directory specified, and GHIDRA_HOME isn't set")
        ghidra_dir = pathlib.Path(ghidra_dir)
        if not ghidra_dir.exists():
            raise GeneratorException(f"Provided Ghidra directory {ghidra_dir} does not exist!")
    else:
        ghidra_dir = pathlib.Path(ghidra_dir)

    # Check MSVC
    msvc_dir = pathlib.Path(args.msvc_dir)
    if not msvc_dir.exists() and msvc_dir.is_dir():
        print(f"Error: {msvc_dir} doesn't exist or isn't a directory!")
        return  
    # Check SDK
    sdk_dir = pathlib.Path(args.sdk_dir)
    if not sdk_dir.exists() and sdk_dir.is_dir():
        print(f"Error: {sdk_dir} doesn't exist or isn't a directory!")
        return
    if out_path := args.out:
        out_path = pathlib.Path(out_path)
    else:
        out_path = SDK_ROOT / sdk_dir.stem

    # Create output path
    if out_path.exists():
        if out_path.parent.parent.stem == PROJECT_NAME:
            # Safe to delete. DEBUG: not deleting 
            # shutil.rmtree(out_path)
            pass
        else:
            # Meh
            print(f"Error: Output path already exists! Delete existing output directory first.")
            return
    out_path.mkdir(exist_ok=True)
    if args.mode == CPP_MODE:
        data_dir = out_path / CPP_SDK_DIR
    else:
        data_dir = out_path / C_SDK_DIR
    data_dir.mkdir(exist_ok=True)
    extra_includes = []
    if args.phnt:
        extra_includes.append(PHNT_ROOT)
        # Prepend the PH files with '_' so they get processed first instead of potentially incomplete windows types
        if args.mode == CPP_MODE:
            phnt_src = data_dir / '0ProcessHacker.cpp'
            phnt_src.write_text(PHNT_CPP)
        else:
            phnt_src = data_dir / '0ProcessHacker.c'
            phnt_src.write_text(PHNT_C)
        phnt_traverse = data_dir / '0ProcessHacker.traverse.json'
        phnt_traverse.write_text(json.dumps(PHNT_TRAVERSE))

    # Parse
    parse_win32metadata(data_dir, args.mode)
    parse_sdk(data_dir, sdk_dir, msvc_dir, args.mode, extra_includes)
    parse_constants(data_dir, sdk_dir)
    create_gdt(data_dir, ghidra_dir)

CPP_ONLY = [
    'alljoyn_c\\\\autopinger.h',
    'textserv.h',
    'dbgmodel.h',
    'dxcapi.h',
    'dcomp.h',
    'directml.h',
    'dwrite.h',
    'dwrite_1.h',
    'dwrite_2.h',
    'dwrite_3.h',
    'mpeg2psiparser.h',
    'il21dec.h',
    'iwstdec.h',
    'vpconfig.h',
    'vpnotify.h',
    'amxmlgraphbuilder.h',
    'dmoimpl.h',
    'infotech.h',
    'reconcil.h',
    'mrmresourceindexer.h',
    'mpeg2data.h',
    'atscpsipparser.h',
    'dvbsiparser.h',
    'bdatif.h',
    'prnasntp.h',
    'evalcom2.h',
    'msctfmonitorapi.h',
    'vswriter.h',
    'mileffects.h',
    'uiautomationcoreapi.h',
    'dispatcherqueue.h',
    'windows.graphics.effects.interop.h',
    'windows.graphics.interop.h',
    'windows.ui.composition.interop.h',
    'roparameterizediid.h',
    'windows.ai.machinelearning.native.h',
    'scclient.h',
    'wmpplug.h',
    'wmpdevices.h',
]

def null_ns_handler(data):
    return data

def csaddr_handler(data):
    pre = """\
#include <winsock2.h>

"""
    return pre + data

def mf_ns_handler(data):
    pre = """\
#include <windows.h>
#include <sdkddkver.h>
#include <mmreg.h>

"""
    return pre + data

NS_HANDLERS = {
    'FunctionDiscovery': csaddr_handler,
    'Mf': mf_ns_handler,
    'Ndf': csaddr_handler,
    'WebServicesOnDevices': csaddr_handler,
}

if __name__ == "__main__":
    main()
