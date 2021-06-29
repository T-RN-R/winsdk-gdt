import argparse
import json
import pathlib
import re
import shlex
import subprocess
import typing

SDK_DIR = pathlib.Path(r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0")
MSVC_DIR = pathlib.Path(
    r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.29.30037"
)
CL_ARGS = [
    '/GS',
    '/W1',
    '/Zc:wchar_t',
    '/Zi',
    '/Gm-',
    '/O2',
    '/Zc:inline',
    '/fp:precise',
    '/errorReport:prompt',
    '/WX-',
    '/Zc:forScope',
    '/Gd',
    '/MD',
    '/FC',
    '/EHsc',
    '/nologo',
    '/diagnostics:column',
    '/d1reportAllClassLayout',
]
# TBD whether we should support providing the architecture?
POINTER_SIZE = 8

class ClException(Exception):
    pass

def parse_class_layouts(raw):
    # Convert raw MSVC output from /d1reportAllClassLayout into json
    class_pattern = re.compile("class\s+([^\s]+)\s+size\((\d+)\):\s*\t\+\-\-\-\s*(.+?)(?=\t\+\-\-\-)\t\+\-\-\-", flags=re.DOTALL)
    field_pattern = re.compile("(\d+).+(?:(?:\+\-\-\-)|(?:\|))(.*)")
    vftable_pattern = re.compile("([^\:\s]+::\$vftable@[^\:]*):\s*(.+?)(?=\n\S)", flags=re.DOTALL)
    class_defs = []
    raw_str = raw.decode('utf-8')
    
    def parse_field_defs(fields_raw):
        fields = []
        for field_def in fields_raw.splitlines():
            if field_match := field_pattern.match(field_def.strip()):
                field_offset = int(field_match.group(1))
                field_name = field_match.group(2).strip()
                if 'base class' in field_name:
                    # Skip base class entries in class definitions
                    continue
                fields.append((field_offset, field_name))
        return fields
                
    # Classes
    for match in class_pattern.findall(raw_str):
        class_name = match[0]
        class_size = int(match[1])
        fields_raw = match[2]
        if '<unnamed-tag>' in class_name:
            # Skip anonymous structs/unions in this output since we can't tell who they belong to :)
            continue
        class_def = {'name': class_name, 'size': class_size, 'fields': parse_field_defs(fields_raw)}
        class_defs.append(class_def)

    # Vftables
    for match in vftable_pattern.findall(raw_str):
        class_name = match[0]
        fields_raw = match[1]
        fields = parse_field_defs(fields_raw)
        class_size = len(fields) * POINTER_SIZE
        class_def = {'name': class_name, 'size': class_size, 'fields': fields}
        class_defs.append(class_def)

    return class_defs

def dump_class_layouts(
    msvc_dir: pathlib.Path,
    src_files: typing.List[pathlib.Path],
    inc_paths: typing.List[pathlib.Path],
    ):

    cl_path = msvc_dir / 'bin/Hostx64/x64/cl.exe'
    msvc_inc = msvc_dir / 'include'
    if not cl_path.exists():
        raise ClException(f"cl.exe not found at {cl_path}")
    cl_args = ' '.join(CL_ARGS)
    # Add user-provided includes along with the MSVC include directory
    cl_includes = ' '.join(f'/I"{x.as_posix()}"' for x in inc_paths)
    cl_includes += f' /I"{msvc_inc}"'
    for src_file in src_files:
        output_file = src_file.with_suffix('.classes.json')
        if output_file.exists():
            continue
        cl_cmdline = f'"{cl_path}" {cl_args} {cl_includes} {src_file.as_posix()}' 
        print(cl_cmdline)
        cl_proc = subprocess.Popen(
            shlex.split(cl_cmdline), stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        cl_out, cl_err = cl_proc.communicate()
        if cl_err:
            raise ClException(str(cl_err, encoding="utf-8"))
        class_defs = parse_class_layouts(cl_out)
        output_file.touch()
        json.dump(class_defs, output_file.open('w'), indent=2)
        # debug file
        # src_file.with_suffix('.classes.debug').write_text(str(cl_out, encoding="utf-8"))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-files", nargs="+", required=True)
    parser.add_argument("--msvc-dir", required=False, default=None)
    parser.add_argument("--include-paths", nargs="+", required=False)
    args = parser.parse_args()

    # Validate source files
    src_files = []
    for filename in args.source_files:
        filepath = pathlib.Path(filename)
        if not filepath.exists():
            raise FileNotFoundError(f"Source file {filename} was not found.")
        src_files.append(filepath)

    msvc_dir = pathlib.Path(args.msvc_dir) if args.msvc_dir else MSVC_DIR
    if not msvc_dir.exists():
        raise FileNotFoundError(f"MSVC directory {msvc_dir} was not found.")

    includes = []
    for dirname in args.include_paths or []:
        dirpath = pathlib.Path(dirname)
        if not dirpath.exists() and dirpath.is_dir():
            raise FileNotFoundError(f"Extra include directory {dirname} was not found.")
        includes.append(dirpath)

    dump_class_layouts(
        msvc_dir,
        src_files,
        includes,
    )

if __name__ == "__main__":
    main()