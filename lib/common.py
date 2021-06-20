#!/usr/bin/env python
# coding=utf-8

""" common.py: Small common functions
 
Created by b1ueshad0w on 5/12/16.
"""

import os
import re
import time
import json
import shutil
import zipfile
import random
import string
from subprocess import Popen, PIPE, check_output, CalledProcessError, check_call
import logging
# from business.configparser import Config
# from thirdpartylib import psutil
import stat
# from configHandler import Config
# import lib.log
from tempfile import mkstemp, mkdtemp
import tempfile
from contextlib import contextmanager

logger = logging.getLogger(__name__ if __name__ != '__main__' else os.path.splitext(os.path.basename(__file__))[0])
logger.setLevel(logging.DEBUG)

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))

HOME = os.environ['HOME']

UDID_DEVICE_PATTERN = re.compile(r'[a-f\d]{40}')
UDID_SIMULATOR_PATTERN = re.compile(r'^[\dA-F]{8}-[\dA-F]{4}-[\dA-F]{4}-[\dA-F]{4}-[\dA-F]{12}$')
IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
CRASH_MAC_PATTERN = re.compile(r'(.+)_(.+)_(.+).crash')

IPHONE_OS_ARCHS = ['armv7', 'armv7s', 'arm64']
IPHONE_SIMULATOR_ARCHS = ['x86_64', 'i386']

SERVER_PATH = os.path.join(PROJECT_ROOT, 'xct', 'wdarpcserver.py')

TEST_RES = 'TestResources'


@contextmanager
def pushd(new_dir):
    """ Temporarily changing working directory. See a usage in 'app2ipa'. """
    origin_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(origin_dir)


def md5(file_path):
    import hashlib
    hash = hashlib.md5()
    # hash = hashlib.sha1()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda : f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()


def sha1(file_path):
    import hashlib
    # hash = hashlib.md5()
    hash = hashlib.sha1()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda : f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()


def is_exe(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)


def which(program):
    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


class TempDir(object):
    def __init__(self):
        self._path = mkdtemp()

    def __enter__(self):
        return self._path

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.remove()

    def remove(self):
        if not self._path or not os.path.exists(self._path):
            return
        shutil.rmtree(self._path)


class SDK(object):
    iphone_simulator = 'iphonesimulator'
    iphone_os = 'iphoneos'


def check_arch(arch_str):
    """ This is used to check if the arch string passed to xcodebuild is valid. Return corresponding sdk option for
    xcodebuild.
    1. To build both for real device and simulator is not allowed.
    2. To build both for i386 and x86_64 is not allowed
    """
    items = arch_str.split(' ')
    has_iphone_os, has_iphone_sim = False, False
    sim_count = 0
    for item in items:
        if item in IPHONE_OS_ARCHS:
            has_iphone_os = True
            continue
        elif item in IPHONE_SIMULATOR_ARCHS:
            has_iphone_sim = True
            sim_count += 1
            continue
        logger.warning('Illegal arch: %s' % item)
        return False
    if has_iphone_os and has_iphone_sim:  # Rule 1
        logger.warning('Building both for iphoneos and iphonesimulator is not allowed.')
        return False
    if sim_count >= 2:  # Rule 2
        logger.warning('Building both for i386 and x86_64 is not allowed.')
        return False
    return SDK.iphone_os if has_iphone_os else SDK.iphone_simulator


def get_binary_arch_type(bianry_path):
    """
    Output may be one of the following forms:
     Non-fat file: /tmp/libmonkey/Build/Products/Debug-iphoneos/libxx.dylib is architecture: arm64
     Architectures in the fat file: /tmp/libmonkey/Build/Products/Debug-iphoneos/libxx.dylib are: armv7 arm64
    """
    cmd = 'lipo -info %s' % bianry_path

    try:
        output = check_output(cmd, shell=True)
        arm_str = output.strip().split(': ')[-1]
        return arm_str
    except CalledProcessError as e:
        logger.error('Command %s failed: %s' % (cmd, e.output))


def get_app_arch_type(app_path):
    """ Return arch str like: 'armv7 arm64' """
    exec_name = get_app_properties(app_path)['CFBundleExecutable']
    exec_path = os.path.join(app_path, exec_name)
    return get_binary_arch_type(exec_path)


def get_ipa_arch_type():
    pass


def safe_check_call(cmd, shell=True):
    try:
        logger.debug('$ %s' % cmd)
        check_call(cmd, shell=shell)
        return True
    except CalledProcessError as e:
        logger.error('Failed: %s' % e.output)
        return False


def safe_check_output(cmd, shell=True):
    try:
        logger.debug('$ %s' % cmd)
        output = check_output(cmd, shell=shell)
        return output
    except CalledProcessError as e:
        logger.error('Failed: %s' % e.output)
        return False


def get_app_executable_path(app_path):
    """ Support .app .framework """
    return os.path.join(app_path, get_app_properties(app_path)['CFBundleExecutable'])


class PackageType(object):
    ipa = 'ipa'
    app = 'app'
    dylib = 'dylib'
    framework = 'framework'

    @staticmethod
    def get_type(file_path):
        if file_path.endswith('.ipa'):
            return PackageType.ipa
        elif file_path.endswith('.app'):
            return PackageType.app
        elif file_path.endswith('.framework'):
            return PackageType.framework
        elif file_path.endswith('.dylib'):
            return PackageType.dylib


def app2ipa_deprecated(app_path, ipa_path):
    if not os.path.isdir(app_path):
        logger.error('App file not exist: %s' % app_path)
        return False
    arch_str = get_app_arch_type(app_path)
    platform = check_arch(arch_str)  # 'iphonesimulator' or 'iphoneos'
    cmd = '/usr/bin/xcrun -sdk %s PackageApplication -v %s -o %s' % (platform, app_path, ipa_path)
    # if not safe_check_call(cmd):
    if not safe_check_output(cmd):
        return False
    return True


def app2ipa(app_path, ipa_path):
    if os.path.isfile(ipa_path):
        os.remove(ipa_path)
    with TempDir() as temp_dir:
        temp_payload_dir = os.path.join(temp_dir, 'Payload')
        if os.path.isdir(temp_payload_dir):
            shutil.rmtree(temp_payload_dir)
        os.mkdir(temp_payload_dir)
        new_app_path = os.path.join(temp_payload_dir, os.path.basename(app_path))
        logger.debug('Copying app files...')
        shutil.copytree(app_path, new_app_path)
        logger.debug('Zipping app files...')
        with pushd(temp_dir):
            cmd = 'zip -qyr {ipa} Payload'.format(ipa=ipa_path)
            return os.system(cmd) == 0


def assert_tool_exist(tool_name):
    if not which(tool_name):
        raise RuntimeError('%s not installed.' % tool_name)


def replace(file_path, pattern, subst):
    """ Search and replace a line in a file
    :param file_path: file to edit
    :param pattern: pattern to replace
    :param subst: new content to replace the content of above pattern
    :return: Bool indicates a success or failed
    """
    fh, abs_path = mkstemp()
    with open(abs_path, 'w') as new_file, open(file_path) as old_file:
        for line in old_file:
            new_file.write(line.replace(pattern, subst))
    os.close(fh)
    os.remove(file_path)
    shutil.move(abs_path, file_path)
    return True


def get_app_properties(app_path):
    """ Support: .app .framework
    Return Property Dict (with keys like: CFBundleIdentifier, CFBundleName, CFBundleExecutable
    """
    info_plist_path = os.path.join(app_path, 'Info.plist')
    if not os.path.isfile(info_plist_path):
        logger.warning('Info.plist not exist: %s' % (app_path,))
        return
    return parse_plist(info_plist_path)


def get_ipa_properties(ipa_path):
    """ Get properties from Info.plist file from IPA. """
    temp_path = mkdtemp()
    if ipa_path.endswith('ipa'):
        app_path = extract_app_from_ipa(ipa_path, temp_path)
    else:
        app_path = ipa_path
    property_dict = get_app_properties(app_path)
    if os.path.exists(temp_path):
        shutil.rmtree(temp_path)
    return property_dict


def get_bundle_id_from_ipa(ipa_path):
    temp_path = mkdtemp()
    extract_app_from_ipa(ipa_path, temp_path)
    bundle_id = get_bundle_id_from_app(temp_path)
    if os.path.exists(temp_path):
        shutil.rmtree(temp_path)
    return bundle_id


def get_bundle_id_from_app(app_file_dir):
    app_name = None
    for filename in os.listdir(app_file_dir):
        if filename.endswith('app'):
            app_name = filename
            break
    if not app_name:
        raise RuntimeError('Cannot get bundle ID!')
    property_dict = parse_plist(os.path.join(app_file_dir, app_name, 'Info.plist'))
    return property_dict['CFBundleIdentifier']


def check_url_exists(url):
    logger.debug('Validating url: %s' % (url,))
    import urllib2
    try:
        urllib2.urlopen(url)
        return True
    except (urllib2.HTTPError, urllib2.URLError) as e:
        logger.exception(e)
        return False


def unzip_via_mac_tool(filepath, to_dir):
    """ Using Archive Utility to unzip a zip file """
    # Using Archive Utility to open a ZIP file
    begin_time = time.time()
    time.sleep(1)
    cmd = 'open -a "Archive Utility" %s' % (filepath,)
    logger.debug('executing: %s' % cmd)
    os.system(cmd)
    # Wait for the spawned process (Archive Utility) to finish
    # Sadly we don't know when it will end
    time.sleep(8)
    # Using Archive Utility to open a ZIP file
    # will unzip the file into the same folder.
    # We will find the output by files creating time.
    directory = os.path.dirname(filepath)
    filepaths = [os.path.join(directory, fn) for fn in os.listdir(directory) if not fn.startswith('.')]
    filepaths = [fp for fp in filepaths if os.stat(fp).st_ctime > begin_time]
    # filepaths.sort(key=lambda x: os.stat(x).st_ctime, reverse=True)
    if len(filepaths) != 1:
        raise RuntimeError('Unzip via mac tool (Archive Utility) failed!')
    dest = os.path.join(to_dir, os.path.basename(filepaths[0]))
    os.rename(filepaths[0], dest)


def unzip(zipfile_path, to_dir):
    # logger.debug('zipfile_path: %s' % zipfile_path)
    try:
        zip_file = zipfile.ZipFile(zipfile_path)
        for file_name in zip_file.namelist():
            zip_file.extract(file_name, path=to_dir)
        zip_file.close()
    except zipfile.BadZipfile as e:
        logger.error('[from built-in zipfile module] %s' % e.message)
        unzip_via_mac_tool(zipfile_path, to_dir)


def unzip_app_zip(app_zip_path, to_dir):
    zip_file = zipfile.ZipFile(app_zip_path)
    name_list = zip_file.namelist()
    app_name = name_list[0].rstrip('/')
    for file_name in name_list:
        zip_file.extract(file_name, path=to_dir)
    zip_file.close()
    return os.path.join(to_dir, app_name)


def list_by_creation_date(dire):
    from stat import S_ISREG, ST_CTIME, ST_MODE
    paths = (os.path.join(dire, f) for f in os.listdir(dire))
    stat_and_paths = ((os.stat(path), path) for path in paths)
    # regular files
    creation_date_and_paths = ((stat[ST_CTIME], path) for stat, path in stat_and_paths
                               # if S_ISREG(stat[ST_MODE])
                               )
    files_sorted = sorted(creation_date_and_paths)
    for cdate, path in files_sorted:
        print(time.ctime(cdate), os.path.basename(path))


def unzip_dsym_zip(dsym_zip_path, to_dir):
    unzip(dsym_zip_path, to_dir)
    return find_file_with_type_under_dir('dSYM', to_dir)


def zipdir(path, dest):
    """ Zip files under a directory
    :param path: direcotry path
    :param dest: zip file path
    :return: None
    """
    temp_zip = os.path.join('/tmp', 'tempzip.zip')  # in case of 'dest' is under 'path'
    # os.chdir(path)
    ziph = zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED)
    for root, dirs, files in os.walk(path):
        for f in files:
            if f == '.DS_Store':
                continue
            ziph.write(os.path.join(root, f), f)
    # for f in os.listdir(path):
    #     ziph.write(f, os.path.basename(f))
    ziph.close()
    shutil.copy(temp_zip, dest)
    os.remove(temp_zip)


def extract_app_from_ipa(ipa_file_path, to_dir):
    logger.debug('Extracting IPA to APP...')
    unzip(ipa_file_path, to_dir)
    payload_dir = os.path.join(os.path.join(to_dir, 'Payload'))
    for f in os.listdir(payload_dir):
        if not f.endswith('.app'):
            continue
        app_file_name = f
        break
    else:
        raise RuntimeError('Could not find app file under Payload folder: {payload}'.format(payload=payload_dir))

    from_path = os.path.join(payload_dir, app_file_name)
    output_path = os.path.join(to_dir, app_file_name)
    if os.path.isdir(output_path):
        shutil.rmtree(output_path)
    shutil.move(from_path, output_path)
    shutil.rmtree(payload_dir)
    logger.debug('Done.')

    # In some cases, the CFBundleExecutable file of newly-generated app file may not be executable
    executable_file_name = get_app_properties(output_path)['CFBundleExecutable']
    executable_file = os.path.join(output_path, executable_file_name)
    make_file_executable(executable_file)

    return output_path


def get_account_by_uuid_from_file(account_file_path, uuid):
    with open(account_file_path) as accouts_file:
        # 0 means general
        accounts = [line.split(' ') for line in accouts_file.readlines()
                    if line.startswith(uuid) or line.startswith('0 ')]
        if len(accounts) > 0:
            return accounts[0][1], accounts[0][2].strip()


def find_file_with_type_under_dir(type_str, directory, is_directory=True):
    # for file_ in os.listdir(directory):
    #     if file_.endswith(type_str):
    #         return os.path.join(directory, file_)
    if is_directory:
        for root, dirs, files in os.walk(directory):
            for d in dirs:
                if d.endswith(type_str):
                    return os.path.join(root, d)
    for root, dirs, files in os.walk(directory):
        for f in files:
            if f.endswith(type_str):
                return os.path.join(root, f)


def catch_exception(func):
    """ A decorate function to catch exceptions when calling a method. """
    def wrapper(*args, **kargs):
        try:
            return func(*args, **kargs)
        except Exception as e:
            logger.exception(e)
    return wrapper


def get_option_by_name(name, default=None, raise_exception_if_unset=True):
    """ First use the option set in os.environ. If not exist, find the option in Config.
    Still not exist, we use the default value.
    :param name: option name
    :param default: default value if not found in Config and os.environ
    :return: option value
    """
    if name in os.environ:
        return os.environ[name]
    if hasattr(Config, name) and getattr(Config, name):
        return getattr(Config, name)
    if default:
        return default
    if raise_exception_if_unset:
        raise RuntimeError('Please set option in Config or os.environ: %s' % name)


def to_unicode(s):
    import types
    if type(s) == types.UnicodeType:
        return s
    elif type(s) == types.StringType:
        try:
            return unicode(s, 'utf8')
        except:
            pass
        try:
            return unicode(s, 'gbk')
        except:
            pass
    return unicode(s)


def to_utf8(s):
    return to_unicode(s).encode('UTF8')


def parse_plist(filename):
    """ Pipe the binary plist through plutil and parse the JSON output
    plutil is part of libimobiledevice.
    plistlib.readPlist(filepath) from python 2.6 cannot parse binary plist
    """
    with open(filename, "rb") as f:
        content = f.read()
    args = ["plutil", "-convert", "json", "-o", "-", "--", "-"]
    p = Popen(args, stdin=PIPE, stdout=PIPE)
    p.stdin.write(content)
    out, err = p.communicate()
    try:
        return json.loads(out)
    except Exception as e:
        logger.debug('Plutil convert plist to json failed: [out] %s; [err] %s' % (out, err))
        raise e


def parse_plist_text(filepath):
    """ Parse plist file of textual format. It use python built-in module.
    :param filepath:
    :return:
    """
    import plistlib
    return plistlib.readPlist(filepath)


def modify_plist(plist_path, **kwargs):
    """ CFBundleIdentifier, CFBundleVersion, etc."""
    # /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier com.b1ueshad0w.demo" Payload/demo.app/Info.plist
    cmd_template = '/usr/libexec/PlistBuddy -c "Set :{key} {value}" %s' % plist_path
    success = True
    for key, value in kwargs.items():
        cmd = cmd_template.format(key=key, value=value)
        if not safe_check_call(cmd):
            success = False
    return success


def url_join(*parts):
    """ Join parts of a URL.
    Join: 'http://www.test.com/', 'index.html'
    ==> 'http://www.test.com/index.html'
    :param parts: parts of URL
    :return: URL joined
    """
    return '/'.join([p.strip('/') for p in parts])


def find_parent_recursive(path, depth):
    p = path
    for _ in range(depth):
        p = os.path.dirname(p)
    return p


def kill_process_with_name_and_option(process_name, option_name, option_value):
    """
    Kill processes if match the given name and option key-value.
    Given:
        idevicesyslog -u e23b89aab108fd92b62025d5f2c88dd1fd2cebfe
    Then
        process_name is 'idevicesyslog'
        option_name is '-u'
        option_value is 'e23b89aab108fd92b62025d5f2c88dd1fd2cebfe'
    :param process_name: Name of the process. Case-sensitive.
    :param option_name: Name of the option. Like '-v'
    :param option_value: Value of the option.
    :return:
    """
    from thirdpartylib import psutil
    pids = psutil.pids()
    current_pid = os.getpid()
    for pid in pids:
        if pid == current_pid:
            continue
        try:
            process = psutil.Process(pid)
            if process.name() == process_name:
                args = process.cmdline()
                if option_name not in args:
                    continue
                _value = args[args.index(option_name) + 1]
                if option_value != _value:
                    continue
                logger.debug('Found an process with name {name} of pid {pid} '
                            'using the option {oname}:{value}'.format(name=process_name, pid=pid,
                                                                      oname=option_name, value=option_value))
                process.terminate()
        except (psutil.ZombieProcess, psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def compare_version_string(v1, v2):
    """ Compare two iOS version number: '9.3.2' > '9.3.1'
    We cannot not directly compare the two string. '10' is less than '9'
    """
    v1_fields = v1.split('.')
    v2_fields = v2.split('.')
    for i, item in enumerate(v1_fields):
        try:
            v1_item, v2_item = int(item), int(v2_fields[i])
            if v1_item > v2_item:
                return 1
            elif v1_item < v2_item:
                return -1
            else:
                continue
        except IndexError:
            return 1
    return -1 if len(v2_fields) > len(v1_fields) else 0


def get_main_version(version):
    """ 7.3.1 ==> 7.3 """
    items = version.split('.')
    if len(items) > 2:
        return '.'.join(items[:2])
    return version


def get_xcode_version():
    cmd = 'xcodebuild -version'
    try:
        output = check_output(cmd, shell=True, encoding='utf-8')
    except CalledProcessError as e:
        raise e
    import re
    match = re.match(r'Xcode ([\.\d]+)\nBuild version ([\da-zA-Z]+)', output)
    if not match:
        raise RuntimeError('Could not parse output %s from cmd "%s"' % (output, cmd))
    return match.groups()


XCODE_VERSION = get_xcode_version()[0]


def is_xcode_version_works_for_ios_version(xcode_version, ios_version):
    xcode_main_ver = get_main_version(xcode_version)
    ios_main_ver = get_main_version(ios_version)
    items = xcode_main_ver.split('.')
    items[0] = str(int(items[0]) + 2)
    xcode_main_ver = '.'.join(items)
    return compare_version_string(xcode_main_ver, ios_main_ver) >= 0


def add_sudo(cmd, password):
    if not password:
        return cmd
    return 'echo {password} | sudo -S {cmd}'.format(password=password, cmd=cmd)


def check_cml_tool_exist(tool_name):
    return os.system('which %s' % tool_name) == 0


def umount(dire):
    cmd = 'umount {directory}'.format(directory=dire)
    logger.debug('shell << %s' % cmd)
    try:
        check_call(cmd, shell=True)
        logger.debug('Umounting success.')
        return True
    except CalledProcessError:
        logger.warning('Umounting failed.')
        return False


def random_word(length):
    return ''.join(random.choice(string.lowercase) for _ in range(length))


def check_libimobiledevice_issue_exist():
    """ See GitHub issue: https://github.com/libimobiledevice/libimobiledevice/issues/356
    Return True if the issue exists.
    """
    lock_down_path = '/var/db/lockdown'
    cmd = 'ls %s' % lock_down_path
    try:
        check_call(cmd, shell=True)
        return True
    except CalledProcessError:
        return False


def is_simulator(udid):
    if udid:
        return '-' in udid


class AddressType(object):
    USB = 'usb'
    IP = 'ip'

    @staticmethod
    def get_address_type(address):
        if not address:
            return
        if UDID_DEVICE_PATTERN.match(address):
            return AddressType.USB
        elif IP_PATTERN.match(address):
            return AddressType.IP


class UDIDType(object):
    DEVICE = 'device'
    SIMULATOR = 'simulator'

    @staticmethod
    def get_udid_type(udid):
        if not udid:
            return
        if UDID_DEVICE_PATTERN.match(udid):
            return UDIDType.DEVICE
        elif UDID_SIMULATOR_PATTERN.match(udid):
            return UDIDType.SIMULATOR


def check_rpc_server_running():
    current_pid = os.getpid()
    for pid in psutil.pids():
        try:
            if pid == current_pid:
                continue
            process = psutil.Process(pid)
            if process.name() != 'Python' or not process.cmdline()[1].endswith('wdarpcserver.py'):
                continue
            return True
        except (psutil.ZombieProcess, IndexError, psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return False


def start_rpc_server():
    return os.system('python %s start' % SERVER_PATH) == 0


def stop_rpc_server():
    # current_pid = os.getpid()
    # for pid in psutil.pids():
    #     if pid == current_pid:
    #         continue
    #     try:
    #         process = psutil.Process(pid)
    #         if process.name() != 'Python' or not process.cmdline()[1].endswith('wdarpcserver.py'):
    #             continue
    #         process.kill()
    #         return
    #     except (psutil.ZombieProcess, IndexError, psutil.AccessDenied, psutil.NoSuchProcess):
    #         continue
    return os.system('python %s stop' % SERVER_PATH) == 0


def restart_rpc_server():
    return os.system('python %s restart' % SERVER_PATH) == 0


# ~~~~~~~~~~~~~~~~ For xcodebuild
class XCConfig(object):
    Debug = 'Debug'
    Release = 'Release'


class Architecture(object):
    ARMV7 = 'armv7'
    ARMV7S = 'armv7s'
    ARM64 = 'arm64'
    X86_64 = 'x86_64'


def get_xcode_path():
    cmd = 'xcode-select -p'
    output = check_output(cmd, shell=True)
    return output.strip().replace('/Contents/Developer', '')


def make_file_executable(file_path):
    if not os.path.isfile(file_path):
        return
    st = os.stat(file_path)
    os.chmod(file_path, st.st_mode | stat.S_IEXEC)


if __name__ == '__main__':
    from pprint import pprint
    logging.basicConfig(level=logging.DEBUG)
    # import plistlib
    # file_path = '/Users/newmonkey/Desktop/Automation_Results.plist'
    # pl = plistlib.readPlist(file_path)
    # pprint(pl)
    # dic = get_ipa_properties('/private/tmp/demo.ipa')
    # pprint(dic)
    # zipdir('/Users/gogleyin/Downloads/tst', '/Users/gogleyin/Downloads/hahha.zip')
    # unzip('/tmp/k12_1.0.0.2_iphone_r264_DSYM.zip', '/tmp')
    # print compare_version_string('9.0', '9')
    # print is_xcode_version_works_for_ios_version('7.2', '9.3')
    # print check_libimobiledevice_issue_exist()
    # path = '/tmp/56e58315-c1df-4879-9702-34a859e3fabb.zip'
    # print md5(path)
    # print sha1(path)
    # print check_arch('i386')
    # print check_arch('x86_64')
    # print check_arch('x86_64 arm64')
    # print check_arch('armv7s arm64 armv7')
    # arch = get_binary_arch_type('/tmp/libmonkey/Build/Products/Debug-iphoneos/libxx.dylib')
    # print arch, check_arch(arch)
    # start_rpc_server()
    # stop_rpc_server()
    # restart_rpc_server()
    plist = '/tmp/Info.plist'
    print(modify_plist(plist, CFBundleIdentifier='com.test.ok'))