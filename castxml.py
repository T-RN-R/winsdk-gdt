import argparse
import enum
import pathlib
import shlex
import subprocess
import typing


class Mode(enum.Enum):
    KERNEL = 0
    USER = 1


SDK_DIR = pathlib.Path(r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0")
DOTNET_SDK_DIR = pathlib.Path(
    r"C:\Program Files (x86)\Windows Kits\NETFXSDK\4.7\Include"
)
MSVC_DIR = pathlib.Path(
    r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.29.30037"
)
CL_ARGS = f"/GS /GL /W3 /Gy /Zc:wchar_t /Gm- /Od /Ob0 /sdl /fp:precise /WX- /Gd /P /Oi /MD /GX /EHsc"
CLANG_IGNORES = [
    "-Wno-deprecated-declarations",
    "-Wno-nonportable-include-path",
    "-Wno-pragma-pack",
    "-Wno-ignored-attributes",
    "-Wno-ignored-pragma-intrinsic",
    "-Wno-visibility",
    "-Wno-microsoft-anon-tag",
    "-Wno-microsoft-enum-forward-reference",
    "-Wno-microsoft-include",
    "-Wno-extra-tokens",
    "-Wno-comment",
    "-Wno-expansion-to-defined",
    "-Wno-incompatible-pointer-types-discards-qualifiers",
    "-Wno-missing-declarations",
    "-Wno-macro-redefined",
    "-Wno-microsoft-exception-spec",
    "-Wno-extern-c-compat",
    "-Wno-class-conversion",
    "-Wno-extern-initializer",
    "-Wno-unused-value",
    "-Wno-microsoft-cast",
    "-Wno-delete-incomplete",
    "-Wno-int-to-pointer-cast",
    "-Wno-microsoft-template-shadow",
    "-Wno-invalid-noreturn",
    "-Wno-dynamic-exception-spec",
    "-Wno-microsoft-explicit-constructor-call",
    "-Wno-deprecated-volatile",
    "-Wno-ambiguous-reversed-operator",
]


class CastXMLException(Exception):
    pass


def clang_sdk_includes(sdk_path):
    return (
        f'-I"{sdk_path}\\ucrt" '
        + f'-I"{sdk_path}\\um" '
        + f'-I"{sdk_path}\\shared" '
        + f'-I"{sdk_path}\\winrt" '
        + f'-I"{sdk_path}\\cppwinrt"'
    )


def clang_dotnet_sdk_includes(dotnet_sdk_path):
    return f'-I"{dotnet_sdk_path}\\um"'


def clang_msvc_includes(msvc_dir):
    return f'-I"{msvc_dir}\\include" ' + f'-I"{msvc_dir}\\atlmfc\\include"'


def invoke_castxml(
    src_files: typing.List[pathlib.Path],
    mode: Mode,
    is_cpp: bool,
    sdk_dir: pathlib.Path,
    dotnet_sdk_dir: pathlib.Path,
    msvc_dir: pathlib.Path,
    extra_includes: typing.List[pathlib.Path],
):
    # cl.exe
    cl_bin = msvc_dir / "bin/Hostx64/x64/cl.exe"

    # Extra include paths
    clang_extra_includes = ""
    if extra_includes:
        clang_extra_includes = " ".join(f'-I"{path}"' for path in extra_includes)
    clang_includes = (
        f"{clang_sdk_includes(sdk_dir)} "
        + f"{clang_dotnet_sdk_includes(dotnet_sdk_dir)} "
        + f"{clang_msvc_includes(msvc_dir)} "
        + f"{clang_extra_includes}"
    )

    # Warnings to ignore
    clang_ignores = ""
    if CLANG_IGNORES:
        clang_ignores = " ".join(ignore for ignore in CLANG_IGNORES)

    if is_cpp:
        clang_lang = "c++20"
    else:
        clang_lang = "c99"

    # Clang arguments
    clang_args = ' '.join([
        f"-std={clang_lang}",
        "-fms-extensions",
        "-fshort-wchar",
        "-fms-compatibility",
        "-ferror-limit=1",
        clang_includes,
        clang_ignores,
        "--verbose"
    ])

    for src_file in src_files:
        out_file = src_file.with_suffix(".xml")
        castxml_args = f'castxml.exe --castxml-cc-msvc-c ( "{cl_bin}" "{CL_ARGS}" ) --castxml-output=1 -o "{out_file}" "{src_file}" {clang_args}'
        print(castxml_args)
        castxml_proc = subprocess.Popen(
            shlex.split(castxml_args), stdin=subprocess.PIPE, stderr=subprocess.PIPE
        )
        castxml_out, castxml_err = castxml_proc.communicate()
        print(
            str(castxml_err, encoding="utf-8") if castxml_err else "No stderr output."
        )
        print(
            str(castxml_out, encoding="utf-8") if castxml_out else "No stdout output."
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-files", nargs="+", required=True)
    parser.add_argument(
        "--mode", choices=["user", "kernel"], required=False, default="user"
    )
    parser.add_argument("--sdk-dir", required=False, default=None)
    parser.add_argument("--dotnet-sdk-dir", required=False, default=None)
    parser.add_argument("--msvc-dir", required=False, default=None)
    parser.add_argument("--extra-includes", nargs="+", required=False)
    parser.add_argument("--c++", action="store_true", dest="cplusplus", default=False)
    args = parser.parse_args()

    # Validate source files
    src_files = []
    for filename in args.source_files:
        filepath = pathlib.Path(filename)
        if not filepath.exists():
            raise FileNotFoundError(f"Source file {filename} was not found.")
        src_files.append(filepath)

    mode = Mode[args.mode.upper()]

    sdk_dir = pathlib.Path(args.sdk_dir) if args.sdk_dir else SDK_DIR
    if not sdk_dir.exists():
        raise FileNotFoundError(f"SDK directory {sdk_dir} was not found.")

    dotnet_sdk_dir = (
        pathlib.Path(args.dotnet_sdk_dir) if args.dotnet_sdk_dir else DOTNET_SDK_DIR
    )
    if not dotnet_sdk_dir.exists():
        raise FileNotFoundError(f".NET SDK directory {dotnet_sdk_dir} was not found.")

    msvc_dir = pathlib.Path(args.msvc_dir) if args.msvc_dir else MSVC_DIR
    if not msvc_dir.exists():
        raise FileNotFoundError(f"MSVC directory {msvc_dir} was not found.")

    extra_includes = []
    for dirname in args.extra_includes or []:
        dirpath = pathlib.Path(dirname)
        if not dirpath.exists() and dirpath.is_dir():
            raise FileNotFoundError(f"Extra include directory {dirname} was not found.")
        extra_includes.append(dirpath)

    invoke_castxml(
        src_files=src_files,
        mode=mode,
        is_cpp=args.cplusplus,
        sdk_dir=sdk_dir,
        dotnet_sdk_dir=dotnet_sdk_dir,
        msvc_dir=msvc_dir,
        extra_includes=extra_includes,
    )


if __name__ == "__main__":
    main()
