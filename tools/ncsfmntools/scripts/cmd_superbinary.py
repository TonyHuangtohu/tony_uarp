#
# Copyright (c) 2021 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-4-Clause
#

import os
import io
import zipfile
import sys
import argparse
import subprocess
import base64
import hashlib
import xml.etree.ElementTree as ET
import shutil
import struct

info_file = io.StringIO()

output_superbinary_plist = ''
payloads_dir = ''

class NS:
    pass

def hprint(*a, **kwa):
    '''Like print(), but prints text decorated as hadeline.'''
    tmp = io.StringIO()
    print('')
    print(*a, file=tmp, **kwa)
    print(tmp.getvalue() + '-' * len(tmp.getvalue()))
    print('')

def iprint(*a, **kwa):
    '''Like print(), but prints to a string that will be shown on FINAL SUMMARY.'''
    print(*a, file=info_file, **kwa)

def show_info():
    '''Shows FINAL SUMMARY generated by the iprint() function.'''
    print('')
    print('==============================================================')
    print('                       FINAL SUMMARY')
    print('==============================================================')
    print('')
    print(info_file.getvalue())

def kb(size):
    '''Returns string that shows both bytes and kilobytes of provided size.'''
    kbytes = round(size / 102.4) / 10
    return f'{size} ({kbytes} KB)'

def file_io(file, mode, content=None):
    '''Shortcut for reading/writing entire file at once.'''
    try:
        f = open(file, mode)
        if content is None:
            content = f.read()
        else:
            f.write(content)
        f.close()
        return content
    except:
        generic_except(f'ERROR: Cannot access "{file}" file.')

def unlink_quiet(f):
    try:
        os.unlink(f)
    except:
        pass

def generic_except(text):
    '''Generic exception handling. It must be placed at the except block.'''
    (_, ex, _) = sys.exc_info()
    if isinstance(ex, SystemExit):
        raise
    print(text, file=sys.stderr)
    if (args is not None and args.debug):
        raise
    print(f'    {str(ex)}', file=sys.stderr)
    sys.exit(1)

def cmd_path(path):
    return path.replace('\\', '/').replace('//', '/')

def join_args(args):
    args = args[:]
    for i in range(0, len(args)):
        if args[i].find(' ') >= 0:
            args[i] = '"' + args[i] +'"'
    return ' '.join(args)

def compose_superbinary():
    '''Compose SuperBinary with mfigr2 tool.'''
    global output_superbinary_plist, payloads_dir
    hprint('Composing SuperBinary')

    # Make sure that file does not exists yet
    unlink_quiet(args.out_uarp)

    skip = (args.mfigr2 == 'skip')
    mfigr2 = 'mfigr2' if skip else args.mfigr2

    # Prepare commands arguments
    compose_args = [
        mfigr2,
        'superbinary', 'compose',
        f'metaDataFilepath={cmd_path(args.metadata)}',
        f'plistFilepath={cmd_path(output_superbinary_plist)}',
        f'payloadsFilepath={cmd_path(payloads_dir or ".")}',
        f'superBinaryFilepath={cmd_path(args.out_uarp)}']
    hash_args = [
        mfigr2,
        'superbinary', 'hash',
        f'superBinaryFilepath={cmd_path(args.out_uarp)}']
    verify_args = [
        mfigr2,
        'superbinary', 'show',
        f'superBinaryFilepath={cmd_path(args.out_uarp)}']

    # Show information how to manually run mfigr2
    if skip:
        print('Skipping SuperBinary composing.')
        print('Compose SuperBinary manually with a command:')
        print(join_args(compose_args))
        print('Calculate its hash with a command:')
        print(join_args(hash_args))
        print('Verify its content with a command:')
        print(join_args(verify_args))
        return

    # Execute mfigr2 to compose SuperBinary
    print('Executing subprocess:')
    print(join_args(compose_args))
    subprocess.run(compose_args, shell=False, check=True)

    # Execute mfigr2 to compute hash
    hprint('Calculating SuperBinary hash')
    print('Executing subprocess:')
    print(join_args(hash_args))
    proc = subprocess.run(hash_args, shell=False, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, encoding='utf-8')
    print(proc.stdout)

    # Execute mfigr2 to verify SuperBinary
    hprint('Verifying SuperBinary')
    print('Executing subprocess:')
    print(join_args(verify_args))
    subprocess.run(verify_args, shell=False, check=True)

    # Print SuperBinary hash
    for line in proc.stdout.splitlines():
        if len(line.strip()) > 0:
            iprint('\nSuperBinary hash')
            iprint('        ' + line.strip())


def create_release_notes():
    global output_superbinary_plist

    skip = (args.mfigr2 == 'skip')
    mfigr2 = 'mfigr2' if skip else args.mfigr2

    if os.path.isdir(args.release_notes):
        if args.out_uarp is not None:
            release_notes_dir = os.path.dirname(args.out_uarp)
        else:
            release_notes_dir = os.path.dirname(output_superbinary_plist)
        release_notes_file = os.path.join(release_notes_dir, 'ReleaseNotes.zip')
        zip = zipfile.ZipFile(release_notes_file, 'w', zipfile.ZIP_DEFLATED)
        for file in os.listdir(args.release_notes):
            zip.write(os.path.join(args.release_notes, file), file)
        zip.close()
    else:
        release_notes_file = args.release_notes

    notes_args = [
        mfigr2,
        'superbinary', 'hash',
        f'superBinaryFilepath={cmd_path(release_notes_file)}']

    if skip:
        print('Calculate release notes hash with command:')
        print(join_args(notes_args))
        return

    # Execute mfigr2 to compute hash of release notes
    hprint('Calculating release notes hash')
    print('Executing subprocess:')
    print(join_args(notes_args))
    proc = subprocess.run(notes_args, shell=False, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, encoding='utf-8')
    print(proc.stdout)

    iprint('\nRelease notes hash')
    for line in proc.stdout.splitlines():
        if len(line.strip()) > 0:
            iprint('        ' + line.strip())


def xml_assert(condition, text):
    if not condition:
        raise Exception('XML parsing error: ' + text)


def update_payload(payload):
    global payloads_dir, args
    MCU_BOOT_IMAGE_VERSION_OFFSET = 20
    xml_assert(payload.tag == 'dict', 'Expecting array of dict in "SuperBinary Payloads"')
    # Create initial payload info
    info = NS()
    info.fourcc = '[invalid 4CC]'
    info.name = '[no name]'
    info.file = None
    info.version_item = None
    info.metadata_item = None
    info.hash_item = None
    info.apply_flags = '[default]'
    # Parse XML and fill up the payload info
    for i in range(0, len(payload), 2):
        key = payload[i]
        value = payload[i + 1]
        xml_assert(key.tag == 'key', 'Expecting key-value content in dict')
        key = key.text.lower()
        if key == 'payload 4cc':
            xml_assert(value.tag == 'string', 'Expecting string in "Payload 4CC"')
            info.fourcc = value.text
        elif key == 'payload long name':
            xml_assert(value.tag == 'string', 'Expecting string in "Payload Long Name"')
            info.name = value.text
        elif key == 'payload filepath':
            xml_assert(value.tag == 'string', 'Expecting string in "Payload Filepath"')
            info.file = value.text
        elif key == 'payload version':
            xml_assert(value.tag == 'string', 'Expecting string in "Payload Version"')
            info.version_item = value
        elif key == 'payload metadata':
            xml_assert(value.tag == 'dict', 'Expecting dict in "Payload MetaData"')
            info.metadata_item = value
            for j in range(0, len(value), 2):
                metadata_key = value[j]
                metadata_value = value[j + 1]
                xml_assert(metadata_key.tag == 'key', 'Expecting key-value content in dict')
                metadata_key = metadata_key.text.lower()
                if metadata_key == 'sha-2':
                    xml_assert(metadata_value.tag == 'data', 'Expecting string in "SHA-2"')
                    info.hash_item = metadata_value
                if metadata_key == 'apply flags':
                    try:
                        names = {
                            1 : 'kUARPApplyStagedAssetsFlagsSuccess',
                            2 : 'kUARPApplyStagedAssetsFlagsFailure',
                            3 : 'kUARPApplyStagedAssetsFlagsNeedsRestart',
                            4 : 'kUARPApplyStagedAssetsFlagsNothingStaged',
                            5 : 'kUARPApplyStagedAssetsFlagsMidUpload',
                            6 : 'kUARPApplyStagedAssetsFlagsInUse',
                            255 : 'reset when fully staged'
                        }
                        info.apply_flags = names[int(metadata_value.text)]
                    except:
                        info.apply_flags = '[invalid]'
    xml_assert(info.file is not None, 'Cannot find "Payload Filepath"')
    # Add hash to the XML if missing
    if info.hash_item is None:
        if info.metadata_item is None:
            ET.SubElement(payload, 'key').text = 'Payload MetaData'
            info.metadata_item = ET.SubElement(payload, 'dict')
        ET.SubElement(info.metadata_item, 'key').text = 'SHA-2'
        info.hash_item = ET.SubElement(info.metadata_item, 'data')
    # Determinate directory containing the payload files
    if args.payloads_dir:
        payloads_dir = args.payloads_dir
    else:
        payloads_dir = os.path.dirname(args.input)
    # Read payload file
    payload_file = os.path.join(payloads_dir, info.file)
    payload_content = file_io(payload_file, 'rb')
    # Read payload file version
    file_ver = struct.unpack_from('<BBHL', payload_content, MCU_BOOT_IMAGE_VERSION_OFFSET)
    file_ver = f'{file_ver[0]}.{file_ver[1]}.{file_ver[2]}'
    xml_assert(info.version_item is not None, 'Payload version not provided in the plist file.')
    if not info.version_item.text:
        info.version_item.text = file_ver
    if file_ver != info.version_item.text and not args.skip_version_checks:
        raise Exception(f'Version "{file_ver}" contained in the MCUBoot image "{info.file}" ' +
                        f'does not match version in the plist file "{info.version_item.text}".')
    # Calculate hash
    sha256 = hashlib.sha256(payload_content)
    sha256_bin = sha256.digest()
    sha256_hex = sha256.hexdigest().upper()
    sha256_b64 = base64.b64encode(sha256_bin).decode("utf-8")
    info.hash_item.text = sha256_b64
    # Print payload information in final summary
    iprint(f'\n{info.fourcc} payload')
    iprint(f'        version:     {info.version_item.text}')
    iprint(f'        file ver:    {file_ver}')
    iprint(f'        name:        {info.name}')
    iprint(f'        file:        {payload_file}')
    iprint(f'        size:        {kb(len(payload_content))}')
    iprint(f'        SHA-256:     {sha256_hex}')
    iprint(f'        apply flags: {info.apply_flags}')
    return file_ver


def update_superbinary():
    global output_superbinary_plist, args
    # Read input
    xml_text = file_io(args.input, 'r')
    # Cut header (document type declarations and optionally comments)
    pos = xml_text.find('<plist')
    xml_assert(pos >= 0, 'Cannot find root plist tag')
    xml_header = xml_text[:pos]
    xml_text = xml_text[pos:]
    # Cut footer (may contain comments)
    pos = xml_text.rfind('</plist>')
    xml_assert(pos >= 0, 'Cannot find root plist ending')
    xml_footer = xml_text[pos + 8:]
    xml_text = xml_text[:pos + 8]
    # Parse and modify the XML
    xml = ET.fromstring(xml_text)
    xml_assert(xml.tag == 'plist', 'Expecting plist tag at xml root')
    xml_assert(len(xml) == 1 and xml[0].tag == 'dict', 'Expecting dict inside plist tag')
    xml_superbinary = xml[0]
    payloads_versions = set()
    super_binary_version = None
    for i in range(0, len(xml_superbinary), 2):
        key = xml_superbinary[i]
        value = xml_superbinary[i + 1]
        xml_assert(key.tag == 'key', 'Expecting key-value content in dict')
        if key.text.lower() == 'superbinary firmware version':
            super_binary_version = value
        if key.text.lower() != 'superbinary payloads':
            continue
        xml_assert(value.tag == 'array', 'Expecting array in "SuperBinary Payloads"')
        for payload in value:
            ver = update_payload(payload)
            payloads_versions.add(ver)
    # Check super binary version
    xml_assert(super_binary_version is not None, 'SuperBinary version not provided in the plist file.')
    if not super_binary_version.text:
        max_ver = (0, 0, 0)
        for ver in payloads_versions:
            payload_ver = tuple(int(x) for x in ver.split('.'))
            if payload_ver >= max_ver:
                max_ver = payload_ver
        super_binary_version.text = '.'.join(str(x) for x in max_ver)
    if super_binary_version.text not in payloads_versions and not args.skip_version_checks:
        separator = '", "'
        raise Exception(f'Version "{super_binary_version.text}" contained in the plist file ' +
                        f'does not match version of any of the payloads: "{separator.join(payloads_versions)}".')
    # Get modified XML
    xml_file = io.StringIO()
    ET.ElementTree(xml).write(xml_file,
                              encoding='unicode',
                              short_empty_elements=False,
                              xml_declaration=False)
    # Put back together header, content and footer
    xml_text = xml_header + xml_file.getvalue().strip() + xml_footer
    # Write the output file
    if args.out_plist is not None:
        output_superbinary_plist = args.out_plist
    else:
        output_superbinary_plist = args.input
    file_io(output_superbinary_plist, 'w', xml_text)
    iprint('\nSuperBinary')
    iprint(f'        version:     {super_binary_version.text}')


def create_metadata():
    if os.path.isfile(args.metadata):
        iprint(f'\nMetadata file "{args.metadata}" already exists - keeping it.')
        iprint('')
    else:
        src = os.path.join(os.path.dirname(__file__), '../data/Metadata.plist')
        shutil.copy(src, args.metadata)
        iprint(f'\nSample metadata file "{args.metadata}" created.')


def cli_protected(cmd, argv):
    global args

    # Parse arguments
    args = None
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description='Compose SuperBianry.', add_help=False, prog=cmd)
    parser.add_argument('input', nargs="?", type=str,
                        help='Input SuperBinary plist file. Payload hashes from this file will be '
                             'recalulated. Additionally, it will be used by the other operations '
                             'depending on the rest of the arguments.')
    parser.add_argument('--out-plist', metavar='file', type=str,
                        help='Output SuperBinary plist file. Input will be overridden if this '
                             'argument is omitted.')
    parser.add_argument('--metadata', metavar='file', type=str,
                        help='Metadata plist file. If the file does not exist it will be created '
                             'with the default values. If "--out-uarp" argument is provided the '
                             'metadata plist file will be used to compose a SuperBinary file.')
    parser.add_argument('--out-uarp', metavar='file', type=str,
                        help='Output composed SuperBinary file. "mfigr2" tool will be used to '
                             'compose final SuperBinary file if this argument is provided.')
    parser.add_argument('--payloads-dir', metavar='path', type=str,
                        help='Directory containing payload files for the SuperBinary. By default, '
                             'it is a directory containing the input SuperBinary plist file.')
    parser.add_argument('--release-notes', metavar='path', type=str,
                        help='If the path is a directory, creates release notes ZIP file from it '
                             'and prints its hash. If it is a file, just prints its hash.')
    parser.add_argument('--mfigr2', metavar='path', type=str, default='mfigr2',
                        help='Custom path to "mfigr2" tool. By default, "mfigr2" from PATH '
                             'environment variable will be used. Setting it to "skip" will '
                             'only show the commands without executing them.')
    parser.add_argument('--skip-version-checks', action='store_true',
                        help='Does not check if plist versions matches MCUBoot images versions.')
    parser.add_argument('--debug', action='store_true',
                        help='Show details in case of exception (for debugging purpose).')
    parser.add_argument('--help', action='help',
                        help='Show this help message and exit')

    args = parser.parse_args(argv)

    if args.input is not None:
        update_superbinary()

    if args.metadata is not None:
        create_metadata()

    if args.out_uarp is not None:
        if args.input is None:
            raise Exception('--out-uarp requires input argument')
        if args.input is None:
            raise Exception('--out-uarp requires --metadata argument')
        compose_superbinary()

    if args.release_notes is not None:
        create_release_notes()

    # Show final information
    show_info()


def cli(cmd, argv):
    try:
        cli_protected(cmd, argv)
    except:
        generic_except('ERROR: exception occurred.')