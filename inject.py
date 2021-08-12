#!/usr/bin/env python
# coding=utf-8

""" inject.py: 

Created by b1ueshad0w on 26/12/2016.
"""

import os
import time
import logging
from lib.common import TempDir, extract_app_from_ipa, get_app_executable_path, safe_check_call, PackageType, app2ipa
import shutil
import pkg_resources
import settings

logger = logging.getLogger(__name__ if __name__ != '__main__' else os.path.splitext(os.path.basename(__file__))[0])
logger.setLevel(logging.DEBUG)

INJECTOR_PATH = pkg_resources.resource_filename('tools', 'insert_dylib')


def _inject(bundle_path, dylib_path, injector_path=INJECTOR_PATH, inject_subpath=None):
    """ Inject a dylib into a bundle, or bundle's bundle (e.g. MyApp/Frameworks/AFNetwork.framework
    Cautious: This method will modify app's content.
    :param bundle_path: the origin bundle
    :param dylib_path: filepath of dylib
    :param injector_path: filepath of injector
    :param inject_subpath: Component of the bundle to be injected. If set to None, we will inject bundle itself
    :return: Bool indicating injection success or not
    """
    injectee = os.path.join(bundle_path, inject_subpath) if inject_subpath else bundle_path
    if inject_subpath:
        logger.debug('Injecting bundle\'s component: %s %s' % (bundle_path, inject_subpath))
    else:
        logger.debug('Injecting bundle: %s' % (bundle_path,))
    if not os.path.isfile(dylib_path):
        logger.error('Dylib not exist: %s' % dylib_path)
        return False
    if not os.path.isdir(injectee):
        logger.error('Bundle to inject not exist: %s' % injectee)
        return False
    if not os.path.isfile(injector_path):
        logger.error('Injector not exist: %s' % injector_path)
        return False
    executable_path = get_app_executable_path(injectee)

    # shutil.copy(dylib_path, app_path)
    # fixed_dylib_path = '@executable_path/%s' % (os.path.basename(dylib_path))

    frameworks_path = os.path.join(injectee, 'Frameworks')
    if not os.path.isdir(frameworks_path):
        os.mkdir(frameworks_path)
    shutil.copy(dylib_path, frameworks_path)
    if not inject_subpath:
        fixed_dylib_path = '@executable_path/Frameworks/%s' % (os.path.basename(dylib_path))
    else:
        fixed_dylib_path = os.path.join('@executable_path', inject_subpath, 'Frameworks/%s' % os.path.basename(dylib_path))

    # if creat_flag:
    #     fixed_dylib_path = '@executable_path/Frameworks/%s' % (os.path.basename(dylib_path))
    # else:
    #     fixed_dylib_path = '@rpath/%s' % (os.path.basename(dylib_path))

    logger.debug('Fixed dylib path: %s' % fixed_dylib_path)
    inject_cmd = '%s %s %s %s' % (injector_path, fixed_dylib_path, executable_path, executable_path)
    if not safe_check_call(inject_cmd):
        return False
    logger.debug('Done.')
    return True


def _inject_framework(bundle_path, framework_to_inject, injector_path=INJECTOR_PATH, inject_subpath=None):
    """ Inject a framework into a bundle, or bundle's bundle (e.g. MyApp/Frameworks/AFNetwork.framework)
    Cautious: This method will modify app's content.
    :param bundle_path: the origin bundle to be injected
    :param framework_to_inject: path of the framework to be injected into the bundle
    :param injector_path: filepath of injector
    :param inject_subpath: Component of the bundle to be injected. If set to None, we will inject bundle itself
    :return: Bool indicating injection success or not
    """
    injectee = os.path.join(bundle_path, inject_subpath) if inject_subpath else bundle_path
    if inject_subpath:
        logger.debug('Injecting bundle\'s component: %s %s' % (bundle_path, inject_subpath))
    else:
        logger.debug('Injecting bundle: %s' % (bundle_path,))

    exec_path_for_inject = get_app_executable_path(framework_to_inject)

    if not os.path.isfile(exec_path_for_inject):
        logger.error('Executable for injection not exist: %s' % exec_path_for_inject)
        return False
    if not os.path.isdir(injectee):
        logger.error('Bundle to inject not exist: %s' % injectee)
        return False
    if not os.path.isfile(injector_path):
        logger.error('Injector not exist: %s' % injector_path)
        return False
    executable_path = get_app_executable_path(injectee)

    host_frameworks_path = os.path.join(injectee, 'Frameworks')
    if not os.path.isdir(host_frameworks_path):
        os.mkdir(host_frameworks_path)
    framework_name = os.path.basename(framework_to_inject)
    dest = os.path.join(host_frameworks_path, framework_name)
    if os.path.exists(dest):
        logger.warning('Framework for injection already exist, will overwrite.')
        shutil.rmtree(dest)
    shutil.copytree(framework_to_inject, dest)

    if not inject_subpath:
        fixed_dylib_path = '@executable_path/Frameworks/%s/%s' % (framework_name, os.path.basename(exec_path_for_inject))
    else:
        fixed_dylib_path = os.path.join('@executable_path', inject_subpath, 'Frameworks/%s' % os.path.basename(exec_path_for_inject))

    logger.debug('Fixed dylib path: %s' % fixed_dylib_path)
    inject_cmd = '%s %s %s %s' % (injector_path, fixed_dylib_path, executable_path, executable_path)
    if not safe_check_call(inject_cmd):
        return False
    logger.debug('Done.')
    return True


def _re_codesign_framework(framework_path, signing_identity):
    if not os.path.exists(framework_path):
        return
    sub_framework_dir = os.path.join(framework_path, 'Frameworks')
    if os.path.exists(sub_framework_dir):
        for sub_framework in os.listdir(sub_framework_dir):
            if not sub_framework.endswith('.framework'):
                continue
            sub_framework_path = os.path.join(sub_framework_dir, sub_framework)
            _re_codesign_framework(sub_framework_path, signing_identity)
    _cmd = '/usr/bin/codesign -f -s "%s" %s' % (signing_identity, framework_path)
    if not safe_check_call(_cmd):
        return False


def _re_codesign(app_path, signing_identity, provision_path=None):
    """ This method will modify app's content.
    Now support all kinds of bundle (app, framework, dylib) except IPA
    """
    bundle_type = PackageType.get_type(app_path)
    logger.debug('Re-codesigning %s...' % (bundle_type,))
    if bundle_type == PackageType.framework or bundle_type == PackageType.dylib:
        _cmd = '/usr/bin/codesign -f -s "%s" %s' % (signing_identity, app_path)
        if not safe_check_call(_cmd):
            return False
        return True

    code_signature_folder = os.path.join(app_path, '_CodeSignature')
    if os.path.isdir(code_signature_folder):
        shutil.rmtree(code_signature_folder)
    code_signature_file = os.path.join(app_path, 'CodeResources')
    if os.path.isfile(code_signature_file):
        os.remove(code_signature_file)

    app_provision_path = os.path.join(app_path, 'embedded.mobileprovision')
    if provision_path:
        shutil.copy(provision_path, app_provision_path)

    entitlement_plist_path = os.path.join('/tmp', 'entitlements%s.plist' % int(time.time()))
    if os.path.isfile(entitlement_plist_path):
        os.remove(entitlement_plist_path)
    _cmd = '/usr/libexec/PlistBuddy -x -c "print :Entitlements " /dev/stdin <<< ' \
           '$(security cms -D -i %s) > %s' % (app_provision_path, entitlement_plist_path)
    if not safe_check_call(_cmd):
        return False
    _cmd = "/usr/libexec/PlistBuddy -c 'Set :get-task-allow true' %s" % entitlement_plist_path
    if not safe_check_call(_cmd):
        return False

    frameworks_path = os.path.join(app_path, 'Frameworks')
    if os.path.isdir(frameworks_path):
        # _cmd = '/usr/bin/codesign -f -s "%s" %s/*' % (signing_identity, frameworks_path)
        # if not safe_check_call(_cmd):
        #     return False
        for framework in os.listdir(frameworks_path):
            framework_path = os.path.join(frameworks_path, framework)
            _re_codesign_framework(framework_path, signing_identity)

    rule_file = os.path.join(app_path, 'ResourceRules.plist')
    if os.path.isfile(rule_file):
        _cmd = '/usr/bin/codesign -f -s "%s" ' \
               '--resource-rules %s ' \
               '--entitlements %s %s' % (signing_identity, rule_file, entitlement_plist_path, app_path)
    else:
        _cmd = '/usr/bin/codesign -f -s "%s" ' \
               '--no-strict --entitlements %s %s' % (signing_identity, entitlement_plist_path, app_path)
    if not safe_check_call(_cmd):
        return False
    if os.path.isfile(entitlement_plist_path):
        os.remove(entitlement_plist_path)
    logger.debug('Done.')
    return True


def inject(app_or_ipa, dylib_or_framework, output_path, injector_path=INJECTOR_PATH, inject_subpath=None):
    file_name = os.path.basename(app_or_ipa)
    # file_name_without_extension = os.path.splitext(file_name)[0]
    # output_file_name = file_name.replace(file_name_without_extension, file_name_without_extension + '_injected')
    # output_path = os.path.join(to_dir, output_file_name)
    package_type = PackageType.get_type(app_or_ipa)
    if not package_type:
        logger.error('Unknown filetype to inject: %s' % app_or_ipa)
        return
    if os.path.isdir(output_path):
        shutil.rmtree(output_path)
    if os.path.isfile(output_path):
        os.remove(output_path)
    with TempDir() as temp_dir:
        if package_type == PackageType.app:
            new_app_path = os.path.join(temp_dir, file_name)
            shutil.copytree(app_or_ipa, new_app_path)
        else:
            new_app_path = extract_app_from_ipa(app_or_ipa, temp_dir)

        inject_method = _inject if PackageType.get_type(dylib_or_framework) == PackageType.dylib else _inject_framework
        if not inject_method(new_app_path, dylib_or_framework, injector_path, inject_subpath=inject_subpath):
            logger.error('Injection failed.')
            return

        if output_path.endswith('.ipa'):
            if not app2ipa(new_app_path, output_path):
                return False
        else:
            shutil.move(new_app_path, output_path)
        return True


def re_codesign(app_or_ipa, signing_identity, output_path, provision_path=None):
    """
    Re-codesign APP (or IPA with output_ipa=True) file.
    :param app_or_ipa: filepath of app or ipa
    :param provision_path: filepath of mobile provisioning profile
    :param signing_identity: code signing identity (e.g. iPhone Developer: XXX (XXXXX) )
    :param to_dir: output directory
    :param output_ipa: Will return IPA rather than APP if set to True
    :return: output file path
    """
    file_name = os.path.basename(app_or_ipa)
    # file_name_without_extension = os.path.splitext(file_name)[0]
    # output_file_name = file_name.replace(file_name_without_extension, file_name_without_extension + '_resigned')
    # output_path = os.path.join(to_dir, output_file_name)
    package_type = PackageType.get_type(app_or_ipa)
    if not package_type:
        logger.error('Unknown filetype to re-codesign: %s' % app_or_ipa)
        return
    with TempDir() as temp_dir:
        if package_type == PackageType.app:
            new_app_path = os.path.join(temp_dir, file_name)
            shutil.copytree(app_or_ipa, new_app_path)
        elif package_type == PackageType.ipa:
            new_app_path = extract_app_from_ipa(app_or_ipa, temp_dir)
        elif package_type == PackageType.dylib or package_type == PackageType.framework:
            shutil.copy(app_or_ipa, output_path)
            new_app_path = output_path

        if not _re_codesign(new_app_path, signing_identity, provision_path=provision_path):
            logger.error('Re-codesigning failed.')
            return

        if output_path.endswith('.ipa'):
            if not app2ipa(new_app_path, output_path):
                return False
        else:
            shutil.move(new_app_path, output_path)
        return True


def inject_and_recodesign(app_or_ipa, dylib_or_framework, output_path, provision_path=None, signing_identity=None,
                          injector_path=INJECTOR_PATH, inject_subpath=None):
    file_name = os.path.basename(app_or_ipa)
    package_type = PackageType.get_type(app_or_ipa)
    if not package_type:
        logger.error('Unknown filetype to process: %s' % app_or_ipa)
        return
    if os.path.exists(output_path):
        shutil.rmtree(output_path) if os.path.isdir(output_path) else os.remove(output_path)
    with TempDir() as temp_dir:
        if package_type == PackageType.app or package_type == PackageType.framework:
            new_app_path = os.path.join(temp_dir, file_name)
            shutil.copytree(app_or_ipa, new_app_path)
        else:
            new_app_path = extract_app_from_ipa(app_or_ipa, temp_dir)

        inject_method = _inject if PackageType.get_type(dylib_or_framework) == PackageType.dylib else _inject_framework
        if not inject_method(new_app_path, dylib_or_framework, injector_path, inject_subpath=inject_subpath):
            logger.error('Injection failed.')
            return

        if provision_path and signing_identity:
            if not _re_codesign(new_app_path, signing_identity, provision_path=provision_path):
                logger.error('Re-codesigning failed.')
                return

        if output_path.endswith('.ipa'):
            if not app2ipa(new_app_path, output_path):
                return False
        else:
            shutil.move(new_app_path, output_path)
        return True


def recodesign_framework_recursively(framework_path, signing_identity, output_file_path=None):
    input_path = framework_path
    if output_file_path:
        shutil.copy(framework_path, output_file_path)
        input_path = output_file_path

    frameworks_dir = os.path.join(input_path, 'Frameworks')
    if os.path.isdir(frameworks_dir):
        for framework in os.listdir(frameworks_dir):
            if not framework.endswith('.framework'):
                continue
            if not recodesign_framework_recursively(os.path.join(frameworks_dir, framework), signing_identity):
                return False

    _cmd = '/usr/bin/codesign -f -s "%s" %s' % (signing_identity, input_path)
    if not safe_check_call(_cmd):
        return False
    return True




def set_start_arguments():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--app', dest='app', required=True, help='filepath of .app or .ipa')
    parser.add_argument('-d', '--dylib', dest='dylib', required=True, help='filepath of dylib')
    parser.add_argument('-o', '--output', dest='output', required=True, help='filepath of output')
    parser.add_argument('-p', '--provision', dest='provision', required=False,
                        help='filepath of mobile provisioning profile')
    parser.add_argument('-c', '--code_sign', dest='code_sign', required=False,
                        help='code signing identity')
    args = parser.parse_args()
    inject_and_recodesign(args.app, args.dylib, args.output, provision_path=args.provision,
                          signing_identity=args.code_sign)

def find_build_app_by_name(name, arch='iphoneos', scheme='Debug', exec_type='app'):
    derived_path = f'/Users/{settings.USER}/Library/Developer/Xcode/DerivedData/'
    print(f'derived_path: {derived_path}')
    names = os.listdir(derived_path)
    match_name = list(filter(lambda a: a.startswith(f'{name}-'), names))
    assert match_name, f'no matched prodcut {name}'
    assert len(match_name) == 1, f'more than one matches for product {name}'
    app_path = os.path.join(derived_path, match_name[0], 'Build/Products/{scheme}-{arch}/{name}.{exec_type}')
    assert os.path.exists(app_path), f'not found target at: {app_path}'
    return app_path


def test_device():
    # app = f'/Users/{settings.USER}/Library/Developer/Xcode/DerivedData/MboxWorkSpace-cujajvpdcgbgyzccljoqdpcreodd/Build/Products/VideoFusionInhouseDebug-iphoneos/VideoFusionInhouse.app'
    app = f'/Users/{settings.USER}/Downloads/VideoFusionInhouse.app'
    # dylib = f'/Users/gogle/Library/Developer/Xcode/DerivedData/MilkyWay-goqhobdqcwzjttfuumyxvwihqdiq/Build/Products/Debug-iphoneos/MilkyWay.dylib'
    dylib = f'/Users/gogle/Library/Developer/Xcode/DerivedData/ByteInsight-aonolohymyukylecvuvysmllfuaa/Build/Products/Debug-iphoneos/ByteInsight.dylib'
    output = '/tmp/output.app'
    provision = f'/Users/{settings.USER}/Library/MobileDevice/Provisioning Profiles/{settings.PROVISIONING_NAME}.mobileprovision'
    sign = settings.SIGNING_IDENTITY
    ret = inject_and_recodesign(app, dylib, output, provision, sign)
    print(ret)
    cmd = f'ideviceinstaller -i {output}'
    assert os.system(cmd) == 0, 'failed to install app'



if __name__ == '__main__':
    # set_start_arguments()
    test_device()
    # path = find_build_app_by_name('VideoFusion')
    # print(path)


