import argparse
import collections
import json
import os
import pathlib
import re
import typing

SCRIPT_ROOT = pathlib.Path(__name__).parent.absolute()
BUILD_ROOT = SCRIPT_ROOT / "build"
ENUMS_JSON_PATH = SCRIPT_ROOT / "win32metadata/generation/scraper/enums.json"

class ConstantsException(Exception):
    pass

class ParsedEnum(object):
    def __init__(self, name: str, data: dict):
        self.name = name
        self.auto_populate = data.get("autoPopulate")
        self.member_type = data.get("type", "int")
        self.flags = data.get("flags", False)
        self.finished = data.get("finished", False)
        if self.auto_populate:
            self.header = self.auto_populate["header"].lower()
            self.filter = self.auto_populate["filter"]
        else:
            self.header = None
            self.filter = None
        self.raw_members = data.get("members", [])
        self.uses = data.get("uses", [])
        self.members = {}

    def dump(self):
        return self.__dict__
        
class EnumParser(object):
    
    CASTS = [
        '(DWORD)',
        '(NTSTATUS)',
        '(int)',
        '(uint)',
    ]

    NOOPS = [
        'unchecked'
    ]

    MISTAKES = {
        'UPDFCACHE_NODATACACHE_': 'UPDFCACHE_NODATACACHE',
        'UPDFCACHE_ONSAVECACHE_': 'UPDFCACHE_ONSAVECACHE',
        'UPDFCACHE_ONSTOPCACHE_': 'UPDFCACHE_ONSTOPCACHE',
        'UPDFCACHE__IFBLANKORONSAVECACHE': 'UPDFCACHE_IFBLANKORONSAVECACHE',
        'UPDFCACHE__ALLBUTNODATACACHE': 'UPDFCACHE_ALLBUTNODATACACHE',
        'GCLP__HBRBACKGROUND': 'GCLP_HBRBACKGROUND',
        'CRYPT_ACQUIRE__WINDOWS_HANDLE_FLAG': 'CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG',
        'SWP__NOOWNERZORDER': 'SWP_NOOWNERZORDER',
        'CFM_UNDERLINE.': 'CFM_UNDERLINE',
        'FILEOP_COPY.': 'FILEOP_COPY',
        'CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG_': 'CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG',
        'PP_SMARTCARD_GUID_': 'PP_SMARTCARD_GUID',
        'CERT_STORE_MAXIMUM_ALLOWED': 'CERT_STORE_MAXIMUM_ALLOWED_FLAG',
        'IMEPADREQ_GETCURRENTUILANG': 'IMEPADREQ_GETCURRENTUILANGID',
        'PERF_AGGREGATE_MAX_': 'PERF_AGGREGATE_MAX',
        '_IPSEC_SA_BUNDLE_FLAG_NLB': 'IPSEC_SA_BUNDLE_FLAG_NLB',
        '_IPSEC_SA_BUNDLE_FLAG_NO_MACHINE_LUID_VERIFY': 'IPSEC_SA_BUNDLE_FLAG_NO_MACHINE_LUID_VERIFY',
        '_IPSEC_SA_BUNDLE_FLAG_NO_IMPERSONATION_LUID_VERIFY': 'IPSEC_SA_BUNDLE_FLAG_NO_IMPERSONATION_LUID_VERIFY',
        '_IPSEC_SA_BUNDLE_FLAG_NO_EXPLICIT_CRED_MATCH' :'IPSEC_SA_BUNDLE_FLAG_NO_EXPLICIT_CRED_MATCH',
        'IPSEC_POLICY_FLAG_KEY_MANAGER_ALLOW_NOTIFY_KEY_': 'IPSEC_POLICY_FLAG_KEY_MANAGER_ALLOW_NOTIFY_KEY',
        'IKEEXT_CERT_AUTH_FLAG_DISABLE_CRL_CHECK__': 'IKEEXT_CERT_AUTH_FLAG_DISABLE_CRL_CHECK',
        'IKEEXT_KERB_AUTH_FORCE_PROXY_ON_INITIATOR_': 'IKEEXT_KERB_AUTH_FORCE_PROXY_ON_INITIATOR',
        'SI_ADVANCED_': 'SI_ADVANCED',
        'SI_CONTAINER_': 'SI_CONTAINER',
        'SI_EDIT_ALL_': 'SI_EDIT_ALL',
        'SI_EDIT_AUDITS_': 'SI_EDIT_AUDITS',
        'SI_EDIT_OWNER_': 'SI_EDIT_OWNER',
        'SI_EDIT_PERMS_': 'SI_EDIT_PERMS',
        'SI_EDIT_PROPERTIES_': 'SI_EDIT_PROPERTIES',
        'SI_NO_ACL_PROTECT_': 'SI_NO_ACL_PROTECT',
        'SI_NO_TREE_APPLY_': 'SI_NO_TREE_APPLY',
        'SI_OBJECT_GUID_': 'SI_OBJECT_GUID',
        'SI_OWNER_READONLY_': 'SI_OWNER_READONLY',
        'SI_OWNER_RECURSE_': 'SI_OWNER_RECURSE',
        'SI_PAGE_TITLE_': 'SI_PAGE_TITLE',
        'SI_READONLY_': 'SI_READONLY',
        'SI_RESET_': 'SI_RESET',
        'SI_RESET_DACL_TREE_': 'SI_RESET_DACL_TREE',
        'SI_RESET_SACL_TREE_': 'SI_RESET_SACL_TREE',
        'SI_SERVER_IS_DC_': 'SI_SERVER_IS_DC',
        'INHTTP_AUTH_SCHEME_DIGEST': 'WINHTTP_AUTH_SCHEME_DIGEST',
    }

    IGNORED_CONSTANTS = [
        'POWER_PLATFORM_ROLE_CURRENT_VERSION', # Doesn't exist?
        '0__zero_',
        'IS_TEXT_UNICODE_BUFFER_TOO_SMALL', # Doesn't exist?
        'AM_TIMECODE_FLAG_FCM',
        'AM_TIMECODE_FLAG_CF',
        'AM_TIMECODE_FLAG_FIELD',
        'AM_TIMECODE_FLAG_DF',
        'AM_TIMECODE_COLORFRAME',
        'AM_TIMECODE_COLORSEQUENCE',
        'AM_TIMECODE_FILMSEQUENCE_TYPE',
        '0x5_-_0x000FFFFF',
        '0x00100000_to_0xFFF00000',
        '_127'

    ]

    IGNORED_ENUMS = [
        'TEXT_STORY_ACTIVE_STATE',
        'DTTOPTS_iTextShadowTypeFlags', # This one exists as a real enum TEXTSHADOWTYPE
    ]

    def __init__(self, win32md_enums_json: pathlib.Path, include_dirs: list[pathlib.Path]):
        self.resolved_constants = {}
        self.parsed_enums: typing.Dict[str, ParsedEnum] = collections.OrderedDict()
        self.deferred_evaluations = collections.defaultdict(lambda: collections.defaultdict(str))
        self.includes: typing.Dict[str, pathlib.Path] = {}
        for include_dir in include_dirs:
            # Glob all of the SDK headers 
            for header in include_dir.glob('*.h'):
                self.includes[header.name.lower()] = header
    
        # These are the headers we need to collect enums from (via win32metadata's enums.json)
        enum_entries = json.load(win32md_enums_json.open('r'))
        enum_entries.extend(EXTRA_ENUMS)
        for enum_entry in enum_entries:
            if enum_name := (enum_entry.get('name') or enum_entry.get('addUsesTo')):
                if enum_name in self.IGNORED_ENUMS:
                    continue
                parsed_enum = ParsedEnum(enum_name, enum_entry)
                self.parsed_enums[enum_name] = parsed_enum

        # Read all #defines from the sdk :o
        constants_json_file = BUILD_ROOT / 'constants.json'
        if constants_json_file.exists():
            self.all_constants = json.load(constants_json_file.open('r'))
        else:
            self.all_constants = self.read_constants_from_headers(self.includes.keys())
            # Dump everything we pulled out
            json.dump(self.all_constants, constants_json_file.open('w'), indent=2)
        
        for header, defines in EXTRA_CONSTANTS.items():
            self.all_constants.update(self.read_constants_from_lines(header, defines))

        # Now iterate over the parsed enum entries to gather complete information
        for parsed_enum in self.parsed_enums.values():
            
            if parsed_enum.auto_populate:
                self.auto_populate(parsed_enum)
            
            for member in parsed_enum.raw_members:
                
                if member['name'] in self.IGNORED_CONSTANTS:
                    continue

                # Wow, these are really messy..
                if member['name'].endswith('.') or member['name'].endswith('_') or '__' in member['name']:
                    print(f"Likely documentation issue in variable {member['name']}")
                
                # Check if it's one of the mistakes in the docs
                if member['name'] in self.MISTAKES:
                    member['name'] = self.MISTAKES[member['name']]

                # Did we already resolve it?
                if member['name'] in parsed_enum.members:
                    continue
                
                # Is there a value provided?
                if "value" in member:
                    constant_entry = {
                        'name': member['name'],
                        'value': member['value'],
                        'header': ''
                    }
                else:
                    # Resolve it ourselves..
                    try:
                        constant_entry = self.all_constants[member['name']]
                    except Exception as e:
                        print(f"Error: {e}")
                
                parsed_value = self.resolve(parsed_enum, constant_entry)
                if parsed_value:
                    parsed_enum.members[member['name']] = parsed_value
                    self.resolved_constants[member['name']] = parsed_value
                else:
                    self.deferred_evaluations[member['name']] = {
                        'enum': parsed_enum,
                        'constant': constant_entry
                    }

        # Process deferred evaluations (forward-declared #defines)
        while self.deferred_evaluations:
            found = []
            for constant_name, deferred_evaluation in self.deferred_evaluations.items():
                parsed_value = self.resolve(
                    deferred_evaluation['enum'], 
                    deferred_evaluation['constant'], 
                    deferred=True
                )
                if parsed_value != None:
                    if deferred_evaluation['enum']:
                        deferred_evaluation['enum'].members[constant_name] = parsed_value
                    self.resolved_constants[constant_name] = parsed_value
                    found.append(constant_name)
            [self.deferred_evaluations.pop(x) for x in found]



        enums_json_file = BUILD_ROOT / 'parsed_enums.json'
        dumped = [pe.dump() for pe in self.parsed_enums.values()]
        json.dump(dumped, enums_json_file.open('w'), indent=2)

    def get_enum(self, name):
        if name not in self.parsed_enums:
            self.parsed_enums[name] = ParsedEnum(name)
        return self.parsed_enums[name]

    def auto_populate(self, parsed_enum: ParsedEnum):
        # Check our constants for entries matching the filter
        def filter_constants(filter_str):
            filtered_constants = []
            for constant_name, constant_info in self.all_constants.items():
                if constant_name.startswith(filter_str) and constant_info['header'] == parsed_enum.header:
                    filtered_constants.append(constant_info)
            return filtered_constants

        filtered = []
        for filter_str in parsed_enum.filter.split('|'):
            filtered.extend(filter_constants(filter_str))

        for constant_entry in filtered:
            # Only grab enums from the named header when auto-populating
            if '(' in constant_entry['value']:
                # Skip function macros..?
                continue
            
            parsed_value = self.resolve(parsed_enum, constant_entry)
            if parsed_value != None:
                parsed_enum.members[constant_entry['name']] = parsed_value
                self.resolved_constants[constant_entry['name']] = parsed_value
                if not parsed_enum.header:
                    parsed_enum.header = constant_entry['header']

    def read_constants_from_lines(self, header, lines: list[str]):
        defines_re = re.compile('#\s*define\s+([^\s]+)([^/\n\r]+)?')
        constants = {}
        cur_define = ''
        for line in lines:
            line = line.strip()
            if cur_define:
                cur_define += ' ' + line
                if line.endswith('\\'):
                    # Continuation of existing define, strip the continuation character
                    cur_define = cur_define[:-1]
                    continue
                else:
                    # Parse this define now
                    define = defines_re.match(cur_define)
            elif define := defines_re.match(line):
                if line.endswith('\\'):
                    cur_define = line[:-1]
                    continue
            else:
                continue
            if not define.group(2):
                # No value, continue
                continue
            constant = define.group(1).strip()
            value = define.group(2).strip()
            constants[constant] =  {
                'header': header,
                'value': value,
                'name': constant
            }
            cur_define = ''
        return constants

    def read_constants_from_headers(self, headers: list[os.PathLike]):
        all_constants = {}
        for header in headers:
            include_raw = self.includes[header].read_text()
            constants = self.read_constants_from_lines(header, include_raw.splitlines())
            all_constants.update(constants)
        return all_constants

    def resolve(self, parsed_enum, constant_entry, deferred=False):
        # Aim to handle substitution cases: 
        #   where a constant is BASE + offset
        #   integers, hex, surrounded by brackets,
        #   simple math?
        int_re = '^(?:(0x[a-fA-F0-9]+|[0-9]+)U?L?)$'
        value = constant_entry['value']        
        # Inconsistent data in here.. whew
        if isinstance(value, int):
            return value

        value = value.replace(' ', '')
        if int_match := re.match(int_re, value):
            int_str = int_match.group(1)
            if int_str.startswith('0x'):
                return int(int_str, 16)
            return int(int_str)

        def sub_cast(match):
            match_str = match.group(1)
            if match_str in self.CASTS:
                return ''
            return match.group(0)

        def sub_fn(match):
            fn_str = match.group(1)
            fn_val = match.group(2)
            if fn_str in self.NOOPS:
                return fn_val
            return match.group(0)

        def sub_value(match):
            match_str = match.group(1)
            # Is this a known constant?
            if value := self.resolved_constants.get(match_str):
                return str(value)
            elif const_entry := self.all_constants.get(match_str):
                return str(const_entry['value'])
            return match_str

        def sub_ref(match):
            return match.group(1)

        # Replace enum references
        value = re.sub("(?:[a-zA-Z_][a-zA-Z0-9_]*\.)+([a-zA-Z_][a-zA-Z0-9_]*)", sub_ref, value)
        # Replace non-operative functions
        value = re.sub("([a-zA-Z_][a-zA-Z0-9_]*)\((.*)\)", sub_fn, value)
        # Replace casts
        value = re.sub("(\([a-zA-Z_][a-zA-Z0-9_]*\))", sub_cast, value)
        # Try to replace known constants if possible
        value = re.sub("([a-zA-Z_][a-zA-Z0-9_]*)", sub_value, value)
        # Strip L from hex strings
        value = re.sub("((?:0x[a-fA-F0-9]+)|(?:[0-9]+))U?L", '\\1', value)

        if not value:
            raise Exception(f"null value for {constant_entry['value']}")

        # Evaluate it.. :x?
        try:
            value = eval(value)
        except NameError as ne:
            if not deferred:
                deferred_constant = {
                    'name': constant_entry.get('name'),
                    'header' : constant_entry.get('header'),
                    'value': value
                }
                self.deferred_evaluations[constant_entry['name']] = {
                    'enum': parsed_enum, 
                    'constant': deferred_constant
                }
            else:
                # Update the value
                constant_entry['value'] = value
            return None
        return value

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdk-dir', help='Source file to preprocess', required=True)
    args = parser.parse_args()
    # Check SDK
    sdk_dir = pathlib.Path(args.sdk_dir)
    if not sdk_dir.exists() and sdk_dir.is_dir():
        print(f"Error: {sdk_dir} doesn't exist or isn't a directory!")
        return
    sdk_includes = [
        sdk_dir / 'ucrt',
        sdk_dir / 'um',
        sdk_dir / 'shared',
        sdk_dir / 'winrt',
        sdk_dir / 'cppwinrt',
    ]
    parser = EnumParser(ENUMS_JSON_PATH, sdk_includes)   

EXTRA_CONSTANTS = {
    'wingdi.h': [
        '#define CLIP_DFA_OVERRIDE CLIP_DFA_DISABLE',
    ],
    'winnls.h': [
        '#define LOCAL_USE_CP_ACP 0x40000000'
    ],
    'winuser.h': [
        '#define KLF_UNLOADPREVIOUS 0x00000004',
        '#define Windows.Win32.UI.WindowsAndMessaging.Apis.WM_USER 0x400'
    ],
    'winsxs.h': [
        '#define IASSEMBLYCACHE_UNINSTALL_DISPOSITION_HAS_INSTALL_REFERENCES 0x00000005',
        '#define IASSEMBLYCACHE_UNINSTALL_DISPOSITION_REFERENCE_NOT_FOUND 0x00000006',
        '#define QUERYASMINFO_FLAG_GETSIZE 0x00000002',
    ],
    'dcomp.h': [
        '#define COMPOSITIONSURFACE_READ 0x00000001',
        '#define COMPOSITIONSURFACE_WRITE 0x00000002',
        '#define COMPOSITIONSURFACE_ALL_ACCESS 0x00000003',
    ],
    'xprtdefs.h': [
        '#define ED_BASE 0x1000',
        '#define ED_DEVCAP_TIMECODE_READ ED_BASE+25',
        '#define ED_DEVCAP_ATN_READ ED_BASE+951',
        '#define ED_DEVCAP_RTC_READ ED_BASE+954',
    ],    
}

EXTRA_ENUMS = [
    {
        "name": "SECURITY_DESCRIPTOR_CONTROL",
        "type": "ushort",
        "flags": True,
        "members": [
            { 
                "name": "SE_OWNER_DEFAULTED",
                 "value": "(0x0001)"
            },
            { 
                "name": "SE_GROUP_DEFAULTED",
                 "value": "(0x0002)"
            },
            { 
                "name": "SE_DACL_PRESENT",
                 "value": "(0x0004)"
            },
            { 
                "name": "SE_DACL_DEFAULTED",
                 "value": "(0x0008)"
            },
            { 
                "name": "SE_SACL_PRESENT",
                 "value": "(0x0010)"
            },
            { 
                "name": "SE_SACL_DEFAULTED",
                 "value": "(0x0020)"
            },
            { 
                "name": "SE_DACL_AUTO_INHERIT_REQ",
                 "value": "(0x0100)"
            },
            { 
                "name": "SE_SACL_AUTO_INHERIT_REQ",
                 "value": "(0x0200)"
            },
            { 
                "name": "SE_DACL_AUTO_INHERITED",
                 "value": "(0x0400)"
            },
            { 
                "name": "SE_SACL_AUTO_INHERITED",
                 "value": "(0x0800)"
            },
            { 
                "name": "SE_DACL_PROTECTED",
                 "value": "(0x1000)"
            },
            { 
                "name": "SE_SACL_PROTECTED",
                 "value": "(0x2000)"
            },
            { 
                "name": "SE_RM_CONTROL_VALID",
                 "value": "(0x4000)"
            },            { 
                "name": "SE_SELF_RELATIVE",
                 "value": "(0x8000)"
            },
        ]
    },
    {
        "name": "OBJECT_TYPE_LIST_LEVEL",
        "type": "ushort",
        "flags": False,
        "members": [
            {
                "name": "ACCESS_OBJECT_GUID",
                "value": "0"
            },
            {
                "name": "ACCESS_PROPERTY_SET_GUID",
                "value": "1"
            },
            {
                "name": "ACCESS_PROPERTY_GUID",
                "value": "2"
            },
            {
                "name": "ACCESS_MAX_LEVEL",
                "value": "4"
            }
        ]
    },
]

if __name__ == "__main__":
    main()

