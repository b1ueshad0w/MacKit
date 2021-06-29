#!/usr/bin/env python
# coding=utf-8

""" parsetsan.py: 

Created by b1ueshad0w on 24/04/2017.
"""

import re
import os
import logging

logger = logging.getLogger(__name__ if __name__ != '__main__' else os.path.splitext(os.path.basename(__file__))[0])
logger.setLevel(logging.DEBUG)

TSAN_PATTERN = '==================(.+?)=================='
SUMMARY_PATTERN = 'SUMMARY: ThreadSanitizer: (.+)'
ADDRESS_PATTERN = '\((\S+):x86_64\+(0x[a-f0-9]+)\)'
ADDRESS_RE = re.compile(ADDRESS_PATTERN)


def is_tsan_crash_log(crash_path):
    if not crash_path or not os.path.isfile(crash_path):
        return False
    with open(crash_path) as f:
        return 'ThreadSanitizer' in f.read()


def get_tsan_from_content(content):
    matches = re.findall(TSAN_PATTERN, content, flags=re.DOTALL)
    return matches


def get_tsan_from_file(file_path):
    with open(file_path) as f:
        return get_tsan_from_content(f.read())


def get_summary_from_tsan(tsan):
    match = re.search(SUMMARY_PATTERN, tsan)
    if not match:
        logger.warning('Cannot get summary from tsan.')
        return
    return match.group(1).replace('x86_64+', '')


def get_tsan_addresses_from_content(content):
    matches = ADDRESS_RE.findall(content)
    addresses = {}
    if not matches:
        logger.debug('No match found for fetching tsan addresses.')
        return
    for match in matches:
        exec_name, address = match
        if exec_name not in addresses:
            addresses[exec_name] = set()  # set initialize
        addresses[exec_name].add(address)
    return addresses


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    f = '~/Documents/crashlogs/simulators/kk/tsan/kk_2017-04-20-132053_TKPC15031FFK.crash'
    tsans = get_tsan_from_file(f)
    for tsan in tsans:
        print(get_summary_from_tsan(tsan))
