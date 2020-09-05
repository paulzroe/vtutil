#!/usr/bin/env python
from __future__ import print_function

__description__ = "Python Tool to search VT"
__author__ = 'PaulK'
__version__ = '0.0.1'
__date__ = '2020/08/23'

"""
History:
    2020/08/23: start

"""

import argparse
import datetime
import logging
import os
import sys
from pprint import pprint
from thirdparty.tablestream import tablestream

import vtutil

# constants
LOG_TO_FILE = False  # log output to a file
LOG_DIR = 'logs'
basename = os.path.splitext(sys.argv[0])[0]
LOGGING_FILENAME = os.path.join(LOG_DIR, basename + '.log')


def extract_hunt_info(filter_str, limit, print_only=False, date_from=None):
    logging.debug("Filter String: {} - Limit: {}".format(filter_str, limit))

    hunts = vt3.get_hunting_notification_files(filter=filter_str, limit=limit)

    hunt_infos = {"count": len(hunts),
                  "info": []}
    color_scheme = None
    if print_only:
        tstream = tablestream.TableStream(
            column_width=(33, 4, 20, 100, 10),
            header_row=('md5', 'hits', 'rule', 'Details', 'first_seen'),
            style=tablestream.TableStyleSlim
        )

    for hunt in hunts:
        hunt_attributes = hunt.get('attributes', {})
        sha256 = hunt.get('attributes', {}).get('sha256')
        md5 = hunt.get('attributes', {}).get('md5')
        first_seen_ts = hunt.get('attributes', {}).get('first_submission_date')
        first_seen = datetime.datetime.fromtimestamp(first_seen_ts)
        if date_from:
            fs_date_from = datetime.datetime.strptime(date_from, '%Y-%m-%d')
            if first_seen < fs_date_from:
                logging.debug("Skipping this sha256: {} first_seen: {}".format(sha256, first_seen))
                continue
        rule_name = hunt.get('context_attributes', {}).get('rule_name')
        ruleset_name = hunt.get('context_attributes', {}).get('ruleset_name')
        positives = hunt.get('attributes', {}).get('last_analysis_stats', {}).get('malicious')
        meaningful_name = hunt.get('attributes', {}).get('meaningful_name')
        names = hunt.get('attributes', {}).get('names')
        tags = hunt.get('attributes', {}).get('tags')
        file_type = hunt.get('attributes', {}).get('type_description')
        match_in_subfile = hunt.get('context_attributes', {}).get('match_in_subfile')
        times_submitted = hunt.get('attributes', {}).get('times_submitted')
        unique_sources = hunt.get('attributes', {}).get('unique_sources')
        malware_name_info = vt3.getClassification({"data": {"attributes": hunt_attributes}})
        malware_name = "{}.{}".format(malware_name_info.get('category'), malware_name_info.get('family'))

        info = {"sha256": sha256,
                "md5": md5,
                "rule_name": rule_name,
                "ruleset_name": ruleset_name,
                "first_seen": str(first_seen),
                "positives": positives,
                "file_type": file_type,
                "meaningful_name": meaningful_name,
                "names": names,
                "tags": tags,
                "times_submitted": times_submitted,
                "unique_sources": unique_sources,
                "match_in_subfile": match_in_subfile,
                "malware_name": malware_name
                }

        if print_only:
            color_scheme = None
            if positives < 10:
                color_scheme = 'yellow'
            if positives < 5:
                color_scheme = 'red'
            details = "MALWARE_NAME: {}\nNAME: {}\nFILE_TYPE: {}\nTAGS: {}\nNAMES: {}".format(malware_name, meaningful_name, file_type, ','.join(tags), ','.join(names))
            tstream.write_row((md5, positives, rule_name, details, first_seen),
                              colors=(color_scheme, color_scheme, None, color_scheme, None))
            tstream.write_sep()
        else:
            hunt_infos["info"].append(info)

    if print_only:
        print("Count of files: {}".format(len(hunts)))
        return
    else:
        return hunt_infos


def make_out_dir(arg_out_dir):
    DEFAULT_SAMPLES_DIR = 'temp'

    if arg_out_dir:
        if not os.path.exists(args.out):
            os.makedirs(args.out)
        return arg_out_dir
    else:
        if not os.path.exists(DEFAULT_SAMPLES_DIR):
            os.makedirs(DEFAULT_SAMPLES_DIR)
        return DEFAULT_SAMPLES_DIR



def main(args):


    filter_str = args.filter
    search_filter = args.search
    if args.get_hunt_notifications:
        extract_hunt_info(filter_str, limit=args.limit, print_only=True, date_from=args.first_seen)

    if args.get_hashes:
        sha256es = vt3.getHashesv3(search_filter, args.limit)
        for sha256 in sha256es:
            print("sha256: {}".format(sha256))

    if args.download:
        out_dir = make_out_dir(args.out)
        print("Saving downloaded files to: {}".format(out_dir))

        if vt3.get_file(args.download, out_dir):
            print("{} - Download...SUCCESS".format(args.download))
        else:
            print("{} - Download...ERROR".format(args.download))

    if args.download_list:
        out_dir = make_out_dir(args.out)
        print("Saving downloaded files to: {}".format(out_dir))
        if os.path.isfile(args.download_list):
            with open(args.download_list) as f:
                for line in f.readlines():
                    hash  = line.strip()
                    if vt3.get_file(hash, out_dir):
                        print("{} - Download...SUCCESS".format(hash))
                    else:
                        print("{} - Download...ERROR".format(hash))

        else:
            logging.error("File {} does not exist".format(args.download_list))


def get_args():
    parser = argparse.ArgumentParser(description="This is a tool to for Virustotal")
    parser.add_argument('--get_hunt_notifications', action='store_true',
                        help="Get files hit by your livehunt rules. You can use this in conjunction with --filter")
    parser.add_argument('--filter', type=str,
                        help="This is a filter used in conjunction with other arguments like --get_hunt_notifications")
    parser.add_argument('--limit', type=int, default=40,
                        help="Limit for search and notifications")
    parser.add_argument('--download', type=str, help="Hash of the file you want to download in VT")
    parser.add_argument('--download_list', type=str, help="File containing hashes to download")
    parser.add_argument('--out', type=str, help="Output dir to save files, pcaps, etc")
    parser.add_argument('--first_seen', help="First seen date from to show, e.g. 2020-01-30. This is useful when "
                                             "filtering new files only")
    parser.add_argument('--search', help='Search VT and return sha256 list. e.g --search "tag:doc positives:10+"')
    parser.add_argument('--get_hashes', action='store_true', help='Get a list of hashes only in conjunction with '
                                                                  '--search e.g., --get_hashes --search positives:10+')
    parser.add_argument('--log', type=str, help="Log level, INFO, DEBUG, WARNING, etc")

    return parser.parse_args()


def set_logging(loglevel):
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    FORMAT = "%(asctime)s:%(levelname)s:[%(filename)s: - %(funcName)20s() ]  %(message)s"

    if LOG_TO_FILE:
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
        logging.basicConfig(filename=LOGGING_FILENAME, level=numeric_level, format=FORMAT)
        logging.debug("Logging to file {}".format(LOGGING_FILENAME))
    else:
        logging.basicConfig(level=numeric_level, format=FORMAT)
        logging.debug("Logging is set to stdout")


if __name__ == '__main__':
    args = get_args()

    try:
        from config import vt_api_key
    except:
        raise

    if args.log:
        set_logging(args.log)
    # else:
    #     set_logging("INFO")

    vt3 = vtutil.VTUtilsV3(vt_api_key)
    main(args)
