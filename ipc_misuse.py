#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
-------------------------------------------------
@File    : ipc_misuse.py
@Time    : 31/1/23 9:41 am
@Author  : Han0nly
@Github  : https://github.com/Han0nly
@Email   : zhangxh@stu.xidian.edu.cn
-------------------------------------------------
"""
import argparse
import json
import os
import ntpath
import glob
import shutil
import subprocess
import threading
import zipfile
import platform
import stat
from pathlib import Path
from androguard.misc import AnalyzeAPK
import logging
from libsast import Scanner
from pymongo import MongoClient

import config

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def format_findings(findings, root):
    """Format findings."""
    for details in findings.values():
        tmp_dict = {}
        for file_meta in details['files']:
            file_meta['file_path'] = file_meta[
                'file_path'].replace(root, '', 1)
            file_path = file_meta['file_path']
            start = file_meta['match_lines'][0]
            end = file_meta['match_lines'][1]
            if start == end:
                match_lines = start
            else:
                exp_lines = []
                for i in range(start, end + 1):
                    exp_lines.append(i)
                match_lines = ','.join(str(m) for m in exp_lines)
            if file_path not in tmp_dict:
                tmp_dict[file_path] = str(match_lines)
            elif tmp_dict[file_path].endswith(','):
                tmp_dict[file_path] += str(match_lines)
            else:
                tmp_dict[file_path] += ',' + str(match_lines)
        details['files'] = tmp_dict
    return findings


def scan(rule, extensions, paths, ignore_paths=None):
    """The libsast scan."""
    try:
        options = {
            'match_rules': rule,
            'match_extensions': extensions,
            'ignore_paths': ignore_paths,
            'show_progress': False}
        scanner = Scanner(options, paths)
        res = scanner.scan()
        if res:
            return format_findings(res['pattern_matcher'], paths[0])
    except Exception:
        logger.exception('libsast scan')
    return {}


def code_analysis(app_dir):
    """Perform the code analysis."""
    try:
        api_rules = Path('android_apis.yaml')
        src = Path(app_dir) / 'java_source'
        src = src.as_posix() + '/'
        skp = config.SKIP_CLASS_PATH
        api_findings = scan(
            api_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        code_an_dic = {
            # change api_findings to privacy_findings
            'api': api_findings
        }
        # print(code_an_dic)
        return code_an_dic
    except Exception:
        logger.exception('Performing Code Analysis')


def update_mobsf_db(app_dic, code_an_dic):
    mobsf_client = MongoClient()
    mobsf_col = mobsf_client["labpc_mobsf_new"][app_dic["store"]]
    record_in_mobsf = mobsf_col.find_one({"file_name": app_dic['app_file']})
    if not record_in_mobsf:
        logger.info(
            "[Cannot find app in mobsf database], continue. (" + app_dic['app_file'][
                                                                     :-4] + ")")
        return None
    logger.info("[Found in the mobsf database]: " + "_" + app_dic['app_file'][:-4])
    record_id = record_in_mobsf["_id"]
    result = record_in_mobsf["result"]
    result["android_api"] = code_an_dic["api"]
    mobsf_col.update_one({"_id": record_id},
                             {"$set": {"result": result}})


def update_violation_db(app_dic, code_an_dic):
    client = MongoClient()
    violation_col = client["permigredb"]['permission']
    # 数据库里面有关于这个app的violation数据的话，就进行处理，更新里面的内容
    record_in_squat = violation_col.find_one({"app_name": app_dic['app_file'][:-4]})
    # record_in_squat = violation_col.find_one({"app_name": record['file_name'][:-4].split("_", 1)[1]})
    # 如果violation数据库中不存在这个app，那么说明这个app的manifest文件缺失
    if not record_in_squat:
        logger.info(
            "[Cannot find app in violation database], continue. (" + app_dic['app_file'][
                                                                     :-4] + ")")
        return None
    logger.info("[Found in the violation database]: " + "_" + app_dic['app_file'][:-4])
    is_invoker = 0
    for i in record_in_squat["requested_permissions"]:
        if not i.startswith("android"):
            if not i.startswith("com.google"):
                # if i not in record["defined_permissions"]:
                # print(record_in_squat["app_name"], "has custom permission", i)
                is_invoker = 1
    record_id = record_in_squat["_id"]
    if "violations" in record_in_squat.keys():
        updated_violations = record_in_squat["violations"]
    else:
        updated_violations = {}
    if is_invoker:
        if len(code_an_dic["api"].keys()):
            # uncheckgrant
            if "api_ipc" in code_an_dic["api"].keys() and "api_check_permission" not in \
                    code_an_dic["api"].keys():
                updated_violations["i2"] = 1
            # uncheckdef
            if "api_ipc" in code_an_dic["api"].keys() and "api_get_certificate" not in \
                    code_an_dic["api"].keys():
                updated_violations["i3"] = 1
        violation_col.update_one({"_id": record_id},
                                 {"$set": {"violations": updated_violations}})


def save_or_update(app_dic, code_an_dic):
    update_mobsf_db(app_dic, code_an_dic)
    update_violation_db(app_dic, code_an_dic)
    # if this machine is without the database environment, we can save the analysis result locally.
    # write2file(app_dic, code_an_dic)


def write2file(app_dic,code_an_dic):
    os.mkdir(app_dic["store"])
    j = json.dumps(code_an_dic, indent=4)
    with open(os.path.join(app_dic["store"], app_dic["app_file"][:-3]+"json"),"w") as f:
        f.write(j)


def find_api(apk_path, apk_filename,store_name):
    if apk_name[-3:] == 'apk':
        app_dic = {}
        # APP DIRECTORY
        logger.info('Starting Analysis on: %s', apk_filename)
        app_dic['app_file'] = apk_filename
        app_dic['store'] = store_name
        app_dic['app_path'] = os.path.join(apk_path, apk_filename)
        app_dic['app_dir'] = os.path.join(config.temp_dir, apk_filename[:-4])
        result_json_dir = config.result_json_dir
        logger.info('Finding %s in result json files', apk_name)
        result_json_fullpath = os.path.join(result_json_dir, apk_filename[:-3] + "json")
        if os.path.exists(result_json_fullpath):
            logger.info('Found result file!')
            with open(result_json_fullpath, "r") as j:
                code_an_dic = json.load(j)
                # print(code_an_dic)
        else:
            apk_2_java(app_dic['app_path'], app_dic['app_dir'])
            # code analysis
            code_an_dic = code_analysis(
                app_dic['app_dir'])
            # Remove the extracted folder
            del_file_or_folder(app_dic['app_dir'])
        logger.info('Connecting to Database')
        try:
            # SAVE TO DB
            logger.info('Updating Database...')
            save_or_update(
                app_dic,
                code_an_dic)
        except Exception:
            logger.exception('Saving to Database Failed')


def apk_2_java(app_path, app_dir):
    """Run jadx."""
    try:
        logger.info('APK -> JAVA')
        args = []
        output = os.path.join(app_dir, 'java_source/')
        logger.info('Decompiling to Java with jadx')
        if os.path.exists(output):
            # ignore WinError3 in Windows
            shutil.rmtree(output, ignore_errors=True)
        jadx = config.JADX_BINARY
        # Set execute permission, if JADX is not executable
        if not os.access(jadx, os.X_OK):
            os.chmod(jadx, stat.S_IEXEC)
        args = [
            jadx,
            '-ds',
            output,
            '-q',
            '-r',
            '--show-bad-code',
            app_path,
        ]
        fnull = open(os.devnull, 'w')
        subprocess.call(args,
                        stdout=fnull,
                        stderr=subprocess.STDOUT)
    except Exception:
        logger.exception('Decompiling to JAVA')


def get_dex_files(app_dir):
    """Get all Dex Files for analysis."""
    glob_pattern = app_dir + '*.dex'
    return glob.glob(glob_pattern)


def filename_from_path(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

# custom: 9171
# any: 46.23%

def dex_2_smali(app_dir):
    """Run dex2smali."""
    try:
        logger.info('DEX -> SMALI')
        dexes = get_dex_files(app_dir)
        for dex_path in dexes:
            logger.info('Converting %s to Smali Code',
                        filename_from_path(dex_path))
            bs_path = config.baksmali
            output = os.path.join(app_dir, 'smali_source/')
            smali = [
                "java",
                '-jar',
                bs_path,
                'd',
                dex_path,
                '-o',
                output,
            ]
            trd = threading.Thread(target=subprocess.call, args=(smali,))
            trd.daemon = True
            trd.start()
    except Exception:
        logger.exception('Converting DEX to SMALI')


def del_file_or_folder(file_path):
    if os.path.exists(file_path):
        try:
            if os.path.isdir(file_path):
                logger.info('Removing directory: %s', file_path)
                shutil.rmtree(file_path, ignore_errors=True)
            else:
                os.remove(file_path)
                logger.info('Removing file: %s', file_path)
        except Exception as error:
            logger.error(error)
    else:
        pass


if __name__ == '__main__':
    file_path = config.apk_dir
    # file_path = os.path.join('/Users/zxh/PycharmProjects/PermSquatting/resources/test_apk')
    stores = ['baidu']
    # stores = ['coolapk']
    for col in stores:
        col_file_path = os.path.join(file_path, col)
        apk_list = os.listdir(col_file_path)
        for apk_name in apk_list:
            # logger.info('analyzing %s ...', apk_name)
            # source = os.path.join(file_path, apk_name)
            try:
                find_api(col_file_path, apk_name, col)
            except BaseException as ee:
                logger.info('%s 检测失败, err: %s', apk_name, ee)
            finally:
                # custom：11529
                # all：20138
                pass

