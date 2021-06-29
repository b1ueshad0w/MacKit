#!/usr/bin/env python
# coding=utf-8

""" symbolicate.py: 

Created by b1ueshad0w on 6/6/16.
"""

from posix import listdir
import re
import os
import shutil
import logging
import subprocess
from lib.common import catch_exception, get_app_properties, TempDir, PackageType, get_xcode_path

Architectures = [
    'armv7',
    'armv7s',
    'arm64',
    'x86_64',
    'arm64e',
]


logger = logging.getLogger(__name__ if __name__ != '__main__' else os.path.splitext(os.path.basename(__file__))[0])
logger.setLevel(logging.DEBUG)

TOOL_PATH = '/Applications/Xcode.app/Contents/SharedFrameworks/' \
            'DVTFoundation.framework/Versions/A/Resources/symbolicatecrash'

ASAN_DYLIB_NAME = 'libclang_rt.asan_ios_dynamic.dylib'
ASAN_DYLIB_NAME_SM = 'libclang_rt.asan_iossim_dynamic.dyli'

DeviceSupportDirRel = 'Library/Developer/Xcode/iOS DeviceSupport'
DeviceSupportDirAbs = os.path.join(os.environ['HOME'], DeviceSupportDirRel)
DylibRel = 'Symbols/usr/lib'
SYSTEM_DSYM_DIR = os.path.join(os.environ['HOME'], 'Library/Developer/Xcode/iOS DeviceSupport', '{iosVersion}',
                               'Symbols/System/Library/Frameworks')
SYSTEM_DSYM_PATH = os.path.join(SYSTEM_DSYM_DIR, '{frameworkName}.framework/{frameworkName}')
SYSTEM_DYLIB_DSYM_DIR = os.path.join(os.environ['HOME'], 'Library/Developer/Xcode/iOS DeviceSupport', '{iosVersion}',
                               'Symbols/usr/lib')
SYSTEM_DYLIB_DSYM_PATH = os.path.join(SYSTEM_DSYM_DIR, '{frameworkName}.framework/{frameworkName}')

OS_VERSION_PATTERN = 'iPhone OS ([\d\.]+) \((\S+)\)'  # iPhone OS11.0(15A5327g)


def _check_output(output, bundle_name):
    begin_pattern = '## Warning: '
    # Using .dSYM file may cause this warning:
    #   ## Warning: Can't find any unstripped binary that matches version of
    #   /var/containers/Bundle/Application/4779EF56-FCFC-4C14-95AB-D44F7FA9DA0B/kk.app/kk
    mid_pattern = 'Can\'t find any unstripped binary that matches version of '
    # Using .app file may cause this warning:
    #   ## Warning: Unable to symbolicate from required binary: /private/tmp/crash2/kk.app/kk
    mid_pattern_2 = 'Unable to symbolicate from required binary: '
    for line in output.splitlines():
        if not line.startswith(begin_pattern):
            continue
        logger.warning(line)
        if mid_pattern not in line and mid_pattern_2 not in line:
            continue
        path = line.replace(begin_pattern, '').replace(mid_pattern, '').replace(mid_pattern_2, '')
        if os.path.basename(path) != bundle_name:
            continue
        return False
    return True


def _get_dsym_binary_path(dsym_path):
    dwarf_path = os.path.join(dsym_path, 'Contents/Resources/DWARF')
    if not os.path.exists(dwarf_path):
        logger.warning('This is not a dSYM: %s' % dsym_path)
        return
    filenames = os.listdir(dwarf_path)
    dsym_file_name = None
    for filename in filenames:
        dsym_file_name = filename
        if dsym_file_name.startswith('.'):
            continue
        break
    binary_path = os.path.join(dwarf_path, dsym_file_name)
    return binary_path


def get_arch_from_crash_report(file_path):
    """
    Crash Report Example:
        ...
        Binary Images:
        0x4000 - 0x2f9bfff kk armv7  <1df58a162eda36759ad19b30200db5f3> /var/containers/Bundle/Application/7BCFD10A-01F2-419C-A5B7-28AB445D5325/kk.app/kk
        0x395c000 - 0x396ffff libkk.dylib armv7  <cf8485fa6fd13cbf86751414904d314c> /var/containers/Bundle/Application/7BCFD10A-01F2-419C-A5B7-28AB445D5325/kk.app/libkk.dylib
        ...
    """
    with open(file_path) as crash_report:
        content = crash_report.read()
        sections = content.strip().split('\n\n')
        for section in sections[::-1]:
            if 'Binary Images' not in section:
                continue
            for line in section.splitlines():
                if not line.startswith('0x'):
                    continue
                return line.split(' ')[4]


def get_arch_from_sim_crash_report(file_path):
    with open(file_path) as f:
        content = f.read()
        result = re.search('Code Type:\s+(\S+)', content)
        if not result:
            logger.debug('Could not find code type in: %s' % file_path)
            return
        return result.group(1)


def symbolicate_via_xcode(crash_log_path, app_dsym_pairs, output_file_path):
    """
    :param app_dsym_pairs: tuples of file paths like: ((app1, dsym1), (app2, dsym2), ...)
        App should be at the 0 index
    :param crash_log_path: crash log file path
    :param output_file_path: symbolicated crash log path
    :return: output_file_path
    """
    if os.path.exists(output_file_path):
        os.remove(output_file_path)
    if type(app_dsym_pairs) not in [tuple, list]:
        raise ValueError('Function expects the type of second argument to be a tuple or list.')
    if len(app_dsym_pairs[0]) != 2:
        raise ValueError('Function expects the second argument to be of the format: ((app, dsym), ...)')
    with TempDir() as temp_symbolicate_dir:
        new_pairs = []
        # We should ensure app and dsym exist in the same folder
        for app, dsym in app_dsym_pairs:
            if not app or not dsym or not os.path.exists(app) or not os.path.exists(dsym):
                raise ValueError('Invalid value in app_dsym_pairs: %s' % app_dsym_pairs)
            app_new = os.path.join(temp_symbolicate_dir, os.path.basename(app))
            dsym_new = os.path.join(temp_symbolicate_dir, os.path.basename(dsym))
            shutil.copytree(app, app_new) if os.path.isdir(app) else shutil.copy(app, app_new)
            if app_new != dsym_new:
                shutil.copytree(dsym, dsym_new) if os.path.isdir(dsym) else shutil.copy(dsym, dsym_new)
            new_pairs.append((app_new, dsym_new))

        script_path = TOOL_PATH
        xcode_path = get_xcode_path()
        xcode_dev_path = os.path.join(xcode_path, 'Contents/Developer')
        if not os.path.exists(script_path):
            try:
                logger.debug('Finding Xcode\'s symbolicatecrash tool.')
                _cmd = 'find {xcode} -name symbolicatecrash'.format(xcode=xcode_path)
                script_path = subprocess.check_output(_cmd, shell=True).strip()
            except subprocess.CalledProcessError:
                script_path = os.path.join(os.path.dirname(__file__), 'lib/ios/symbolicatecrash')
        if not script_path or not os.path.exists(script_path):
            logger.error('Symbolication failed: Cannot find Xcode\'s symbolicatecrash tool.')
            return False

        # Sometimes it need .APP file, sometimes it need .dSYM file. I haven't figure it out by now.
        # And I will check if one success otherwise I will use the other.
        # cmd = 'export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer && ' \
        #       '%s -o %s %s -d %s -d %s' % (script_path, output_file_path, crash_log_path, dsym_path, dsym2)
        cmd = 'export DEVELOPER_DIR={xcode_dev} && ' \
              '{script} {crash} -o {output}'.format(xcode_dev=xcode_dev_path, script=script_path,
                                                    crash=crash_log_path, output=output_file_path)
        for _, dsym in new_pairs:
            cmd += ' -d {dsym}'.format(dsym=dsym)
        logger.debug('$ %s' % cmd)
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        logger.debug('> %s' %output)

        executable_name = get_app_properties(new_pairs[0][0])['CFBundleExecutable']
        if not _check_output(output, executable_name):
            logger.debug('Using .dSYM file failed. Now will try using .app file.')
            if os.path.exists(output_file_path):
                os.remove(output_file_path)
            # cmd = cmd.replace(dsym_path, app_path)
            cmd += '-d {dsym}'.format(dsym=app_dsym_pairs[0][0])
            logger.debug('$ %s' % cmd)
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            logger.debug(output)
            if not _check_output(output, executable_name):
                logger.debug('Symbolication using Xcode tool failed: can not symbolicate app symbols.')
                return False

        # logger.debug('Using atos to symbolicate app symbols...')
        logger.debug('Using atos to symbolicate any app symbols that haven\'t been symbolicated.')
        atosed_crash_log = output_file_path + '.atos.txt'
        # atos_for_app(bundle_name, output_file_path, atosed_crash_log, dsym_path)
        super_atos(app_dsym_pairs, output_file_path, atosed_crash_log, support_dylib=True)
        if os.path.exists(output_file_path):
            os.remove(output_file_path)
        shutil.move(atosed_crash_log, output_file_path)

        if not os.path.exists(output_file_path):
            # shutil.copy(crash_log_path, output_file_path)  # 暂时这样先,等弄好还原服务器再改过来.
            logger.error('Symbolication using Xcode tool failed.')
            return False
        logger.debug('Symbolication via Xcode success.')

        return True


@catch_exception
def atos_for_app(app_lib_name, crash_log_path, output_path, dsym_path):
    """ This is abandoned. [super_atos] is far more effective by sending all addresses to atos at a time."""
    arch = get_arch_from_crash_report(crash_log_path)
    dsym_binary_path = _get_dsym_binary_path(dsym_path)
    app_logic_pattern = '(\d+\s+%s\s+(0x[0-9a-f]+)\s+)(0x[0-9a-f]+)\s+\+\s+\d+' % (app_lib_name,)
    app_logic_regex = re.compile(app_logic_pattern)
    with open(crash_log_path) as crash_log_content, open(output_path, 'wb') as output_file:
        lines = crash_log_content.read().split('\n')
        new_lines = []
        for line in lines:
            result = app_logic_regex.match(line)
            if result:
                # print('%s %s' % (result.group(1), result.group(2)))
                remained, stack_addr, load_addr = result.group(1), result.group(2), result.group(3)
                cmd = 'atos -o %s -arch %s -l %s %s' % (dsym_binary_path, arch, load_addr, stack_addr)
                sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                out, err = sub.stdout.read(), sub.stderr.read()
                # out of the form: main (in k12) (AppDelegate.swift:12)
                new_line = remained + out.strip().replace('(in %s) ' % app_lib_name, '')
                # logger.debug(new_line)
                new_lines.append(new_line)
            else:
                new_lines.append(line)
        output_file.write('\n'.join(new_lines))


def system_framework_dsym_dict(ios_version):
    """
    Generate the 'bundle_dsym_pairs' needed by super_atos function to symbolicate system frameworks' addresses.
    Args:
        ios_version: Must contains numeric-code and str-code. e.g. "11.0 (15A5327g)" for iOS 11 beta 9
    Returns:
        dict of format: {'UIKit': '/path/to/UIKit.framework.dSYM/UIKit', ...}
        may return None if the MacOS doesn't contains the corresponding iOS version dSYMs.
    """
    system_framework_dir = SYSTEM_DSYM_DIR.format(iosVersion=ios_version)
    if not os.path.isdir(system_framework_dir):
        logger.warning('System framework directory not exist: %s' % (system_framework_dir,))
        return
    frameworks = os.listdir(system_framework_dir)
    frameworkNames = [f.replace('.framework', '') for f in frameworks]
    pairs = {k: os.path.join(system_framework_dir, k + '.framework', k) for k in frameworkNames}
    # pairs = [(k, os.path.join(system_framework_dir, k + '.framework', k)) for k in frameworkNames]
    return pairs


def system_dylib_dsym_dict(ios_version):
    """
    Generate the 'bundle_dsym_pairs' needed by super_atos function to symbolicate system dylibs' addresses.
    Args:
        ios_version: Must contains numeric-code and str-code. e.g. "11.0 (15A5327g)" for iOS 11 beta 9
    Returns:
        dict of format: {'libobjc.A.dylib': '/path/to/libobjc.A.dylib', ...}
        may return None if the MacOS doesn't contains the corresponding iOS version dSYMs.
    """
    ios_version_dir = list(filter(lambda n: n.startswith(ios_version), os.listdir(DeviceSupportDirAbs)))
    assert ios_version_dir, f'could not found desired version under {DeviceSupportDirAbs}'
    assert len(ios_version_dir) == 1, f'more than one matches: {ios_version_dir}'
    system_dylib_dir = os.path.join(DeviceSupportDirAbs, ios_version_dir[0], DylibRel)
    if not os.path.isdir(system_dylib_dir):
        logger.warning('System dylib directory not exist: %s' % (system_dylib_dir,))
        return
    fnames = os.listdir(system_dylib_dir)
    dylibNames = [f.replace('.framework', '') for f in fnames if f.endswith('.dylib')]
    pairs = {k: os.path.join(system_dylib_dir, k) for k in dylibNames}
    # pairs = [(k, os.path.join(system_framework_dir, k + '.framework', k)) for k in frameworkNames]
    return pairs


def super_atos(bundle_dsym_pairs, crash_log_path, output_path, is_simu=False, support_dylib=False):
    """
    Parse symbols using atos.
    Currently only parse app symbols and its frameworks symbols.
    But you can easily modify it to support parsing system symbols.

    binary_dsym_pairs: Dict of pairs. Each pair contains a bundle name, and a corresponding DSYM file path. If DSYM file
        path is None, the bundle itself will be used to atos.
        e.g. {
            'kk': '/path/to/kk.dSYM',
            'FrameworkA': '/path/to/FrameworkA.dSYM'
            'FrameworkB': None  # It also can be None
            'libkk.dylib': 'libkk.dylib'  # You can also use bundle itself as the dSYM
        }
    :param bundle_dsym_pairs: tuples of file paths like: ((app1, dsym1), (app2, dsym2), ...)
        App should be at the 0 index
    """
    # Bundle name in RQD crash report is the executable name:
    #   kk ==> kk
    #   Foundation ==> Foundation
    #   libdispatch.dylib ==> libdispatch.dylib
    # Bundle name in system-generated crash report on simulators is the bundle id (except for the C bundles)
    #   kk ==> com.b1ueshad0w.kk.dailybuild
    #   Foundation ==> com.apple.Foundation
    #   libdispatch.dylib ==> libdispatch.dylib
    # Bundle name in Last Exception Backtrace of crash report on simulators is the executable name

    # So if the crash_log_path is merged with rqd crash report, the bundle name in Call Stack section will be kk
    # the bundle name in Images section will be com.b1ueshad0w.kk.dailybuild

    if os.path.isfile(output_path):
        os.remove(output_path)

    bundleID2execName = {}  # {'com.b1ueshad0w.mkk': 'kk', ...}
    binary_dsym_dict = {}  # {'kk': '/path/to/kk.app.dSYM', ...}
    for bundle, dsym in bundle_dsym_pairs:
        bundle_type = PackageType.get_type(bundle)
        if bundle_type not in [PackageType.app, PackageType.framework, PackageType.dylib]:
            logger.warning('Un-support package type passing to atos: %s' % (bundle_type,))
            continue
        if bundle_type == PackageType.dylib:
            app_lib_name = os.path.basename(bundle)
            binary_dsym_dict[app_lib_name] = dsym
            continue
        app_info = get_app_properties(bundle)
        app_lib_name = app_info['CFBundleExecutable']
        bundle_id = app_info['CFBundleIdentifier']
        bundleID2execName[bundle_id] = app_lib_name
        binary_dsym_dict[app_lib_name] = dsym

    # arch = get_arch_from_crash_report(crash_log_path)
    sim_arch = get_arch_from_sim_crash_report(crash_log_path) if is_simu else None
    # ATOS does not recognize arch type 'x86
    if sim_arch == 'X86' or sim_arch == 'X86-64':
        sim_arch = 'x86_64'

    with open(crash_log_path) as f:
        content = f.read()
    content = atos_tsan_address(binary_dsym_dict, content)
    content = content.replace('...g_rt.asan_ios_dynamic.dylib', ASAN_DYLIB_NAME).\
        replace('...g_rt.asan_iossim_dynamic.dylib', ASAN_DYLIB_NAME_SM)

    # Add system frameworks' dSYMs
    match = re.search(OS_VERSION_PATTERN, content)
    if not match:
        logger.debug('Cannot find matches for %s from the crash log.' % (OS_VERSION_PATTERN,))
    else:
        version_no, version_code = match.groups()
        version_str = '%s (%s)' % (version_no, version_code)
        system_framework_dict = system_framework_dsym_dict(version_str)
        if system_framework_dict:
            binary_dsym_dict.update(system_framework_dict)
        system_dylib_dict = system_dylib_dsym_dict(version_str)
        if system_dylib_dict:
            binary_dsym_dict.update(system_dylib_dict)

    # 调用行的三种可能性：
    #   a. 行号 库名 实际地址 载入地址 + 323445 （偏移量）
    #   b. 行号 库名 实际地址 符号 + 1238
    #   c. 行号 库名 实际地址 符号 + 1238 （文件名：行号）
    # a其实就是完全为还原；b多出现在模拟器的crash log上, 即未还原完全缺少文件名行号；c为完全还原后（包括文件名和行号）
  # stack_pattern = '\d+\s+(\S+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+\s+\+\s+\d+)'  # For a
    stack_pattern = '\d+\s+(\S+)\s+(0x[0-9a-f]+)\s+(.+\s+\+\s+\d+)'  # For a, b
    stack_regex = re.compile(stack_pattern)

    # image_pattern = '(0x[0-9a-f]+)\s+-\s+0x[0-9a-f]+\s+(\S+)\s+(\S+)\s+.+'
    # It's a little different for Simulator Crash Report
    # 1. There are some blanks at the line beginning
    # 2. There is a '+' in front of the bundle name. e.g. kk => +kk
    # 3. Maybe contains no arch info.
    # e.g.
    # Binary Images:
    #        0x100f27000 -        0x100f29fff +com.b1ueshad0w.MyApp (1.0 - 1) <B167DDE0-6657-3800-9104-91A4121C7568> /Users/USER/Library/Developer/CoreSimulator/Devices/401650DB-05F6-4959-912D-06175D207223/data/Containers/Bundle/Application/E04A23E6-5664-4684-9B04-9DAA84E78F16/MyApp.app/MyApp
    #        0x100f2f000 -        0x100f57717 +dyld_sim (421.0.5) <0A977C48-0BA5-3692-BD87-5CB54F58BD99> /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk/usr/lib/dyld_sim
    image_pattern = '\s*(0x[0-9a-f]+)\s+-\s+0x[0-9a-f]+\s+\+*(\S+)\s+(\S+)\s+.+'

    image_regex = re.compile(image_pattern)
    all_symbols = {}
    all_images = {}
    for line in content.splitlines():
        result = stack_regex.match(line)
        image_result = image_regex.match(line)
        if result:
            lib_name, stack_addr, load_and_offset = result.group(1), result.group(2), result.group(3)
            if lib_name in bundleID2execName:
                # In some crash reports from simulator, lib_name could be the BundleID rather than the executable name
                lib_name = bundleID2execName[lib_name]
            if lib_name not in all_symbols:
                all_symbols[lib_name] = {}
            if stack_addr not in all_symbols[lib_name]:
                all_symbols[lib_name][stack_addr] = load_and_offset
        elif image_result:
            try:
                load_addr, lib_name, _arch = image_result.group(1), image_result.group(2), image_result.group(3)
                if lib_name in bundleID2execName:
                    # In some crash reports from simulator, lib_name could be the BundleID rather than the executable name
                    lib_name = bundleID2execName[lib_name]
                if _arch not in Architectures:
                    if is_simu:
                        _arch = sim_arch
                    else:
                        raise RuntimeError('Unknown architecture type: %s' % _arch)
                all_images[lib_name] = {'LoadAddr': load_addr, 'Arch': _arch}
            except IndexError:
                print(line)
                print(image_result.groups())
                exit(1)
        else:
            continue

    # assert  '+' + app_lib_name in all_images
    # assert app_lib_name in all_images
    for app_lib_name in binary_dsym_dict.keys():
        if app_lib_name in all_images:
            continue
        logger.warning('Cannot find bundle image info from the crash log: %s' % (app_lib_name,))

    for key in all_symbols.keys():
        _used_to_atos = binary_dsym_dict.get(key)
        if not _used_to_atos or not os.path.exists(_used_to_atos):
            continue
        if _used_to_atos.endswith('.dSYM'):  # This could be dSYM, or bundle itself (dylib)
            _used_to_atos = _get_dsym_binary_path(_used_to_atos)
        if not _used_to_atos:
            continue
        # else:
        #     app_path = hostApp
        #     binary_path = os.path.join(app_path, key)
        #     if not os.path.isfile(binary_path):
        #         binary_path = os.path.join(app_path, 'Frameworks', key)
        #     if not os.path.isfile(binary_path):
        #         logger.debug('Skip bundle for missing dSYM: %s' % key)
        #         continue
        #     _used_to_atos = binary_path
        stack_addrs_combines = ' '.join(all_symbols[key].keys())
        cmd = '{tool} ' \
              '-o "{dsym}" ' \
              '-arch {arch} ' \
              '-l {loadAddr} ' \
              '{addrs}'.format(tool='atos', dsym=_used_to_atos,
                               arch=all_images[key]['Arch'], loadAddr=all_images[key]['LoadAddr'],
                               addrs=stack_addrs_combines)
        logger.debug('$ %s' % cmd)
        sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = sub.stdout.read().decode('utf-8'), sub.stderr.read().decode('utf-8')
        if len(out) == 0 and len(err) > 0:
            raise RuntimeError('Symbolication via atos failed: %s' % (err,))
        lines = [e.replace(' (in {LibName})'.format(LibName=key), '') for e in out.strip().splitlines()]
        for i, stack_addr in enumerate(all_symbols[key].keys()):
            content = content.replace(all_symbols[key][stack_addr], lines[i])

    with open(output_path, 'w') as of:
        of.write(content)


def atos_tsan_address(binary_dsym_dict, content):
    from parsetsan import get_tsan_addresses_from_content
    tsan_addresses = get_tsan_addresses_from_content(content)  # {'ExecName': set, 'ExecName2': set}
    if not tsan_addresses:
        return content
    content = re.sub('<null>:\d+ ', '', content)
    for exec_name, addresses in tsan_addresses.items():
        _used_to_atos = binary_dsym_dict.get(exec_name)
        if not _used_to_atos or not os.path.exists(_used_to_atos):
            continue
        if _used_to_atos.endswith('.dSYM'):  # This could be dSYM, or bundle itself (dylib)
            _used_to_atos = _get_dsym_binary_path(_used_to_atos)
        if not _used_to_atos:
            continue
        addresses_combined = ' '.join(addresses)

        cmd = '{tool} ' \
              '-o {dsym} ' \
              '-arch {arch} ' \
              '{addrs}'.format(tool='atos', dsym=_used_to_atos, arch='x86_64', addrs=addresses_combined)
        logger.debug('$ %s' % cmd)
        sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = sub.stdout.read(), sub.stderr.read()
        if len(out) == 0 and len(err) > 0:
            raise RuntimeError('Symbolication via atos failed: %s' % (err,))
        # -[SomeClass someMethod:arg] (in MyApp) (SourceFileName.m:520)    ==>   (in MyApp) (SourceFileName.m:520)
        lines = [e[e.find('(in '):] for e in out.strip().splitlines()]
        for i, addr in enumerate(addresses):
            to_be_replaced = '({exec_name}:x86_64+{addr})'.format(exec_name=exec_name, addr=addr)
            content = content.replace(to_be_replaced, lines[i])
    return content


def set_start_arguments():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--crash_log_path', dest='crash_log_path', required=True, help='file path of crash log')
    parser.add_argument('-a', '--app_path', dest='app_path', required=True, help='file path of .APP')
    parser.add_argument('-d', '--dsym_path', dest='dsym_path', required=True, help='file path of .dSYM')
    parser.add_argument('-o', '--output_path', dest='output_path', required=True, help='file path of output')
    args = parser.parse_args()
    ret = symbolicate_via_xcode(args.crash_log_path, args.app_path, args.dsym_path, args.output_path)
    logger.debug(ret)



if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    import settings
    # set_start_arguments()
    # print get_arch_from_sim_crash_report(crash)
    # testSymbolizeAddressforDeviceCrashReport()
    # crash = '/private/tmp/crash/TestInject-2017-03-10-121330.ips'
    crash = '/private/tmp/crash/VideoFusionInhouse-2021-06-29-172051.ips'
    app = '/private/tmp/symbols/TestInject.app'
    # dsym = '/private/tmp/symbols/TestInject.app.dSYM'
    # dsym2 = '/private/tmp/symbols/Fancy.framework.dSYM'
    dsym = f'/Users/{settings.USER}/Library/Developer/Xcode/DerivedData/MilkyWay-bqtwibvqlsldchgfurtouqhcstyd/Build/Products/Debug-iphoneos/MilkyWay.dSYM'
    dylib_dsym = f'/Users/{settings.USER}/Library/Developer/Xcode/DerivedData/MilkyWay-bqtwibvqlsldchgfurtouqhcstyd/Build/Products/Debug-iphoneos/MilkyWay.dylib.dSYM'
    app_dsym = f'/Users/{settings.USER}/Library/Developer/Xcode/DerivedData/LvWorkspace-alilokyafbvaeobmefurhqzixppw/Build/Products/VideoFusionInhouseDebug-iphoneos/VideoFusionInhouse.app.dSYM'
    # all_dsym = ' '.join([dsym, dsym2])
    # symbolicate_via_xcode(crash, ((app, dsym),), '/tmp/desymbol_full.txt')
    dsyms = (
        ('MilkyWay.dylib', dylib_dsym),
        ('VideoFusionInhouse', app_dsym)
    )
    super_atos(dsyms, crash, '/tmp/new.txt')


