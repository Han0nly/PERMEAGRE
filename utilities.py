# coding=utf-8
import json
import os, sys
import time
from xml.dom.minidom import parse
from xml.parsers.expat import ExpatError

import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
from google_play_scraper import app

#######################################################
# 主要功能：1. 使用Apktool反编译apk文件
#           2. 提取AndroidManifest.xml至manifest文件夹
#           3. 对比activity、receiver、provider组件中使用的权限是否声明或申请
#           4. 保存未声明的权限名及其包名至unclaim.txt文件中
#######################################################
# 使用方法：1.将该代码和所有apk文件放在同一目录
#           2. python3 Analysis_perm.py
# B(1)在主程序里面识别，统计所有的已定义权限，然后与component声明时的权限进行比对
# C(1)在主程序里面识别，统计所有的已定义权限，然后与app声明的权限进行比对
# C(2)搜索checksignature函数与packagename函数
# C(3)搜索检查权限的函数
# C(4)搜索给intent设置权限的函数
######################################################
from pymongo.errors import DuplicateKeyError

apk_dir = ""
# manifest_dir = "/Users/zxh/PycharmProjects/PermSquatting/manifest"
temp_dir = ""

# desdir = "manifest"
# filepath = "./"
# 解压文件

# 先确定合法的attribute和tag
manifestAttributes = []
childOfManifestTag = []
instrumentationAttributes = []
supportsScreensAttributes = []
usesConfigurationAttributes = []
usesFeatureAttributes = []
usesFeatureValues = []
usesSdkAttributes = []
pTreeAttributes = []
pGroupAttributes = []
permissionAttributes = []
usesPermissionAttributes = []
usesPermission23Attributes = []
pRequireFeature = []
featureList = []
currentFeatureList = []
pGroup = []
tempAttributes = []

system_perms = []
with open("Permissions.txt", "r") as perms:
    for perm in perms:
        system_perms.append(perm.strip())

firebase_perms = [
    "com.google.firebase.iid.FirebaseInstanceIdReceiver",
    "com.google.android.c2dm.permission.SEND",
]


def findAllFile(base, ext):
    for root, ds, fs in os.walk(base):
        for f in fs:
            if f.endswith(ext):
                fullname = os.path.join(root, f)
                yield fullname


# 判断comp是否被exported并且被permission保护，如果是的话，则返回其名称及对应的权限信息
def get_target_component_info(comp):
    # 这种寻找方法属于exporter-side的漏洞的寻找方法
    # user-side的寻找需要在代码中进行，首先找到app里面有哪些intent，然后从数据库中找到对应的intent，对比双方permission是否一致
    # print(comp.nodeValue)
    perm = comp.getAttribute("android:permission")
    # print(perm)
    perm_read = comp.getAttribute("android:readPermission")
    # print(perm_read)
    perm_write = comp.getAttribute("android:writePermission")
    # print(perm_write)
    component_info = {'name': comp.getAttribute("android:name")}
    # return None
    if comp.getAttribute("android:enabled") != 'false':
        if comp.getAttribute("android:exported") == 'true' \
                or (
                comp.getAttribute("android:exported") is None and len(comp.getElementsByTagName('intent-filter')) > 0):
            if perm or perm_read or perm_write:
                component_info['android:permission'] = perm
                component_info['android:readPermission'] = perm_read
                component_info['android:writePermission'] = perm_write
                return component_info
    return None


def addornewkey(dic, key):
    if key in dic.keys():
        dic[key] = dic[key] + 1
    else:
        dic[key] = 1
    return dic


def parse_installs(installs):
    if installs:
        installs_str = installs.strip()
        if installs_str.endswith("万"):
            installs_int = float(installs_str[:-1]) * 10000
        elif installs_str.endswith("亿"):
            installs_int = float(installs_str[:-1]) * 100000000
        elif installs_str.endswith('万下载'):
            installs_int = float(installs_str[:-3]) * 10000
        elif installs_str.endswith('亿下载'):
            installs_int = float(installs_str[:-3]) * 100000000
        elif installs_str.endswith('万次'):
            installs_int = float(installs_str[:-2]) * 10000
        elif installs_str.endswith('次'):
            installs_int = float(installs_str[:-1])
        elif installs_str.endswith('下载'):
            installs_int = float(installs_str[:-2])
        else:
            installs_int = float(installs_str)
    else:
        installs_int = 0
    return installs_int


def crawl_install_genre(package_id):
    """Get App Details form Google Play or AppMonsta."""
    try:
        print('[PlayStore] Fetching Details from Play Store: %s' % package_id)
        det = app(package_id)
        det.pop('descriptionHTML', None)
        det.pop('comments', None)
        description = BeautifulSoup(det['description'], features='lxml')
        det['description'] = description.get_text()
        det['error'] = False
        # print(det)
        print('[PlayStore] Found %s in Play Store, minInstalls=%s, genreId=%s' % (
            package_id, det['minInstalls'], det['genreId']))
        return det['minInstalls'], det['genreId']
    except Exception:
        print('[AppMonsta] Cannot find %s in Play Store, searching in AppMonsta' % (package_id))
        # Get the apps' download count information from AppMonsta API
        # Request Parameters
        store = "android"  # Could be either "android" or "itunes".
        country_code = "US"  # Two letter country code.

        req_params = {"country": country_code}

        # Auth Parameters
        # username = "{API_KEY}"  # Replace {API_KEY} with your own API key.
        api_key = "23e3af66c75a4f6081efea3f645221cd7804111b"
        password = "X"  # Password can be anything.

        # Request URL
        request_url = "https://api.appmonsta.com/v1/stores/%s/details/%s.json" % (store, package_id)

        # This header turns on compression to reduce the bandwidth usage and transfer time.
        headers = {'Accept-Encoding': 'deflate, gzip'}
        try:
            # Python Main Code Sample
            response = requests.get(request_url,
                                    auth=(api_key, password),
                                    params=req_params,
                                    headers=headers,
                                    stream=True)
            # json_record = response.json()
            json_record = json.loads(response.content)
            # print(json_record)
            installs = int(json_record['downloads'].replace(",", "").replace("+", ""))
            genre = json_record['genre_id']
            print('[AppMonsta] Found %s in Appmonsta, installs=%s, genre=%s' % (package_id, installs, genre))
            return installs, genre
        except Exception:
            print(
                '[AppMonsta] Cannot find %s in Appmonsta, return 0' % (package_id))
            return 0, ""
        # else:
        #     print('[Only Google Options Disabled] Cannot find %s in Google Play, searching in CoolAPK/Baidu/360 '
        #           'appstore' % package_id)
        #     det = app_search(package_id)
        #     return det


def app_search(app_id):
    """Get app details from CoolAPK and Baidu Appstore"""
    client = MongoClient()
    col = client['App_collection']['ThirdParty']
    re_rule = '.*?\\_' + app_id.replace('.', '\\.') + '\\_v.*'
    record = col.find_one({'ID': {'$regex': re_rule}})
    # print("Regular Expression:", re_rule)
    if record:
        print("Found %s in the database" % app_id)
        installs = record['installs']
        return installs
    else:
        print("[ERROR] Cannot find %s" % app_id)
        return 0


# TODO: Detect only system permissions.
def is_system_perm(perm_name):
    if perm_name in system_perms:
        return True
    else:
        return False


def is_normal_perm(perm_name, defined_normal_perms):
    if perm_name in defined_normal_perms:
        return True
    else:
        return False


def is_irregular_perm(perm_name):
    if perm_name and len(perm_name.split(".")) <= 2:
        return True
    else:
        return False


# 这个函数是为了解析所有的manifest文件并将其中的关键信息存储到mongodb中，
# 第一个参数是manifest文件的路径，
# 第二个参数是只在获取下载量时是否只相信google的数据源，而不相信其他应用市场中的下载量信息。
# 第三个参数是指定是否需要更新数据库中的下载量信息
# 检测了P1,P2,P3,P4四种类型的误用
def extract_info_from_fest2db(manifest_dir, ud, db):
    component_tags = {"activity", "provider", "receiver", "service"}
    client = MongoClient()
    col = client[db]['permission']
    col.create_index([("app_name", 1)], unique=True)
    error_count = 0
    all_enforced_perms = []
    all_unenforced_perms = []
    for file in findAllFile(manifest_dir, 'xml'):
        violation = {}
        # print("Analyzing %s" % file)
        try:
            dom_tree = parse(file)
        except ExpatError:
            print("Error parsing file %s " % file)
            error_count = error_count + 1
            continue
        root_node = dom_tree.documentElement

        # 用来存储关键信息的数据结构
        requested_perms = []
        defined_normal_perms = []
        defined_perms_dict = {}
        defined_dangerous_perms = []
        perm_trees = []
        irregular_perms = []
        enforced_perms = []

        # 找到所有"使用"的permission，存放到requested_perms中
        requested_perm_element_list = root_node.getElementsByTagName(
            "uses-permission") + root_node.getElementsByTagName("uses-permission-sdk-23")
        for p in requested_perm_element_list:
            perm_name = p.getAttribute("android:name")
            requested_perms.append(p.getAttribute("android:name"))
            if is_irregular_perm(perm_name):
                # print("perm_name is", perm_name)
                irregular_perms.append(perm_name)

        # 找到所有"定义"的permission，存放到defined_perms中
        defined_perm_element_list = root_node.getElementsByTagName("permission")
        for p in defined_perm_element_list:
            perm_name = p.getAttribute("android:name")
            perm_protection = p.getAttribute("android:protectionLevel")

            if is_irregular_perm(perm_name):
                # print("perm_name is", perm_name)
                irregular_perms.append(perm_name)

            # 搜索一下protectionLevel是否属于"normal"，"dangerous"，"signature"，"signatureOrSystem"
            if perm_protection == "normal":
                defined_normal_perms.append(perm_name)
            elif perm_protection == "dangerous":
                defined_dangerous_perms.append(perm_name)

            defined_perms_dict[perm_name] = perm_protection

        # 找到所有permission-tree，存放到perm_tree字段中
        perm_tree_element_list = root_node.getElementsByTagName("permission-tree")
        for p in perm_tree_element_list:
            perm_name = p.getAttribute("android:name")
            perm_trees.append(perm_name)

        # 这里获取app中定义的受权限保护的组件
        comp_result = {}
        for tag in component_tags:
            comp_result[tag] = []
            component_list = root_node.getElementsByTagName(tag)
            for component in component_list:
                # print(component)
                component_info = get_target_component_info(component)
                if component_info:
                    p1_violation_perms = []
                    p2_violation_perms = []
                    comp_result[tag].append(component_info)
                    for key in ["android:writePermission", "android:readPermission", "android:permission"]:
                        enforced_perms.append(component_info[key])
                        if is_irregular_perm(component_info[key]):
                            irregular_perms.append(component_info[key])
                        # 检测p1的违规
                        if is_system_perm(component_info[key]) and component_info[key] not in [
                            "android.permission.BIND_JOB_SERVICE",
                            "android.permission.BIND_ACCESSIBILITY_SERVICE",
                            "android.permission.SEND_RESPOND_VIA_MESSAGE",
                            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
                            "android.permission.BIND_WALLPAPER",
                            "android.permission.BIND_REMOTEVIEWS",
                            "android.permission.BIND_VPN_SERVICE",
                            "android.permission.BIND_NFC_SERVICE",
                            "android.permission.BIND_INCALL_SERVICE",
                        ]:
                            p1_violation_perms.append(component_info[key])
                        # 检测p2的违规:是否用了普通权限来保护组件
                        if is_normal_perm(component_info[key], defined_normal_perms):
                            p2_violation_perms.append(component_info[key])
                    if p1_violation_perms:
                        if "p1" in violation.keys():
                            violation["p1"].append({component_info['name']: p1_violation_perms})
                        else:
                            violation["p1"] = [{component_info['name']: p1_violation_perms}]
                    if p2_violation_perms:
                        if "p2" in violation.keys():
                            violation["p2"].append({component_info['name']: p2_violation_perms})
                        else:
                            violation["p2"] = [{component_info['name']: p2_violation_perms}]

        # 检测p4的违规:是否用了不规范的权限名
        irregular_perms = list(set(irregular_perms))
        # print(len(irregular_perms))
        if len(irregular_perms):
            # print("p4 is", irregular_perms)
            violation["p4"] = irregular_perms

        all_enforced_perms = all_enforced_perms + enforced_perms
        defined_perms = defined_perms_dict.keys()
        undefined_but_enfored_perms = [value for value in enforced_perms if
                                       value and (value not in defined_perms) and (value not in system_perms) and not value.startswith("com.google.android")]
        if undefined_but_enfored_perms:
            violation["p3"] = undefined_but_enfored_perms
        non_sig_defined_perms = defined_dangerous_perms + defined_normal_perms
        unenforced_perms = [value for value in non_sig_defined_perms if value not in enforced_perms]
        all_unenforced_perms = all_unenforced_perms + unenforced_perms

        # app_name目前是从文件名中取出来的，主要是为了区分不同的商店中相同的应用。
        app_name = file.split(os.sep)[-1][:-4]
        # appid是从manifest中取出来的app id
        appid = root_node.getAttribute('package')
        if not col.count_documents({"app_name": app_name}):
            print("APP %s doesn't exist in the database, start crawling" % app_name)
            # 最终的数据库结构包含了该app定义的权限，请求的权限，permission-tree，下载量，以及所有组件的名称及设置的权限
            app_info = {'app_name': app_name,
                        "app_ID": appid,
                        "defined_permissions": defined_perms_dict,
                        "requested_permissions": requested_perms,
                        "permission_tree": perm_trees,
                        "activity": comp_result['activity'], "provider": comp_result['provider'],
                        "receiver": comp_result['receiver'], "service": comp_result['service'],
                        "violations": violation, "unenforced": unenforced_perms}
            # print(app_info)
            col.insert(app_info, check_keys=False)
            print("APP record %s successfully stored into the database" % app_name)
        else:
            print("APP record %s already in the database, skipping" % app_name)
            info = {"defined_permissions": defined_perms_dict,
                    "requested_permissions": requested_perms,
                    "permission_tree": perm_trees,
                    "activity": comp_result['activity'], "provider": comp_result['provider'],
                    "receiver": comp_result['receiver'], "service": comp_result['service'],
                    "violations": violation, "unenforced": unenforced_perms}
            col.update_one({"app_name": app_name}, {"$set": info}, True)

    print("Iterating all the manifest files done.")
    print("未使用的权限有以下：", all_unenforced_perms)
    # violation数据库连接
    print("Start to detect I1 violations for all the records in the database, please waiting...")
    # i1：未被enforce的权限
    for record in col.find():
        i1_flag = False
        for i in record["unenforced"]:
            if i in all_enforced_perms:
                i1_flag = True
        if "violations" in record.keys():
            violation = record["violations"]
        else:
            violation = {}
        if i1_flag:
            violation["i1"] = 1
        # violation["has_custom"] = has_custom
        col.update_one({"_id": record["_id"]}, {"$set": {"violations": violation}})


# ManifestInspector(MI) result analysis
def extract_info_from_manifinspector2db(manifest_analysis_result, dbname):
    # m1检测错误的权限defination
    m1_patterns = (  # WrongChild: android:uses-permission <manifest>
        "WrongChild:_permission_<application>",
        "WrongChild:_adopt-permissions_<application>",
        "WrongChild:_adopt-permissions_<manifest>",
        "WrongAttr:_android:logo_<permission>",
        "WrongAttr:_android:logo_<permission>",
        "WrongAttr:_android:priority_<permission-group>",
        "WrongAttr:_android:logo_<permission>",
        "WrongAttr:_android:priority_<permission-group>",
        "WrongAttr:_android:logo_<permission>",
    )

    # m2检测那些错误的request
    m2_patterns = (
        # 错误的属性
        "WrongChild:_uses-permission_<application>",
        "WrongAttr:_aemm:required_<uses-permission>",
        "WrongChild:_uses-permission-sdk-m_<manifest>",
        "WrongChild:_uses-permission_<activity>",
        "WrongChild:_uses-permission_<service>",
        "WrongChild:_user-permission_<manifest>",
        "WrongChild:_use-permission_<manifest>",
        "WrongChild:_use-permission_<receiver>",
        "WrongAttr:_android:label_<uses-permission>",
        "WrongAttr:_android:minSdkVersion_<uses-permission>",
        "WrongAttr:_android:authorities_<uses-permission>",
        "WrongAttr:_android:installLocation_<uses-permission>",
        "WrongAttr:_android:required_<uses-permission>",
        "WrongAttr:_android:protectionLevel_<uses-permission-sdk-23>",
        "WrongAttr:_android:permissionGroup_<uses-permission>",
        "WrongAttr:_android:protectionLevel_<uses-permission>",
        # # 没有使用命名空间
        # "WrongAttr:_name_<permission>",
        # "WrongAttr:_protectionLevel_<permission>",
        # "WrongAttr:_name_<uses-permission>",
        # "WrongAttr:_permission_<service>",
        # "WrongAttr:_permission_<receiver>",
        # "WrongAttr:_permission_<provider>",
        # "WrongAttr:_name_<permission>",
        # "WrongAttr:_protectionLevel_<permission>",
        # "WrongAttr:_description_<permission>",
        # "WrongAttr:_label_<permission>",
        # "WrongAttr:_name_<uses-permission>",
        # "WrongAttr:_protectionLevel_<uses-permission>",
        # "WrongAttr:_permission_<activity>",
        # "WrongAttr:_permission_<activity-alias>",
        # "WrongAttr:_permission_<service>",
        # "WrongAttr:_permission_<receiver>",
        # "WrongAttr:_permission_<provider>",
        # "WrongAttr:_name_<permission>",
        # "WrongAttr:_protectionLevel_<permission>",
        # "WrongAttr:_name_<uses-permission>"
    )

    # m3检测错误的enforcement
    m3_patterns = (  # WrongAttr: android:protectionLevel <uses-permission>
        "WrongAttr:_android-permission_<receiver>",
        "WrongAttr:_android:permission_<manifest>",
        "WrongAttr:_android:protectionLevel_<service>",
        "WrongAttr:_android:protectionLevel_<provider>",
        "WrongAttr:_android:permission_<intent-filter>",
        "WrongAttr:_android:permission_<action>",
        "WrongAttr:_android:protectionLevel_<application>",
        "WrongAttr:_android:protectionLevel_<manifest>",
        "WrongAttr:_android:protectionLevel_<activity>",
        "WrongAttr:_android:protectionLevel_<receiver>",
        "WrongAttr:_android:protectionLevel_<application>",
        "WrongAttr:_android:protectionLevel_<manifest>",
        "WrongAttr:_android:protectionLevel_<activity>",
        "WrongAttr:_android:protectionLevel_<receiver>",
        "WrongAttr:_android:protect_<application>"
    )

    with open(manifest_analysis_result, "r") as f:
        result = {}
        # app_info = {}
        for line in f:
            if line.startswith("[APP]"):
                app_fullpath = line[6:]
                # 这里的app_id是删除了后缀的文件名
                app_name = app_fullpath.split("/")[-1].strip()[:-4]
                app_store = app_name.split("_")[0]
                result[app_name] = {}
                continue

            # M(1) - M(3) Detection
            # if line.startswith("WrongChild:") or line.startswith("WrongAttr:"):
            if line.startswith("WrongChild:") or line.startswith("WrongAttr:"):
                pattern = line.strip().replace(" ", "_").strip(".")
                if pattern in m1_patterns:
                    # 需要排除<protected-broadcast>
                    if "m1" not in result[app_name].keys():
                        result[app_name]["m1"] = []
                    result[app_name]["m1"].append(pattern)
                elif pattern in m2_patterns:
                    if "m2" not in result[app_name].keys():
                        result[app_name]["m2"] = []
                    result[app_name]["m2"].append(pattern)
                elif pattern in m3_patterns:
                    if "m3" not in result[app_name].keys():
                        result[app_name]["m3"] = []
                    result[app_name]["m3"].append(pattern)

            # 暂时不考虑那些识别不出的权限名
            # if line.startswith("P(4)"):
            #     # element = line.split(" ")[1]
            #     perm_name = line.strip().split(" ")[-1]
            #     if perm_name:
            #         if "p4" not in result[app_name].keys():
            #             result[app_name]["p4"] = []
            #         result[app_name]["p4"].append(perm_name)
            #     else:
            #         print("WTF!", line)

    # 将上面的分析结果更新到数据库中
    client = MongoClient()
    col = client[dbname]['permission']

    # appid: 文件名去掉扩展名
    # value: {"m1":{pattern:1},"m2":{pattern:1},"m3":{pattern:1},"p4":{pattern:1}}
    for app_name, value in result.items():
        # print(app_name, value)
        record = col.find_one({"app_name": app_name})
        if record:
            record_violations = record["violations"]
            for violation in value.keys():
                if violation in record_violations.keys() and record_violations[violation]:
                    print(record_violations[violation])
                    record_violations[violation] = record_violations[violation] + value[violation]
                else:
                    record_violations[violation] = value[violation]
            col.update_one({"_id": record["_id"]}, {"$set": {"violations": record_violations}})


def extract_info_from_mobsf2db(mobsf_dbname, dbname):
    # 以前的violation数据库
    old_db = MongoClient()
    old_col = old_db["newresultdb"]["permission"]
    # 新的violation数据库
    violation_client = MongoClient()
    violation_col = violation_client[dbname]['permission']
    db_conn = MongoClient()
    # cols_old = {'bai_new', '360', 'Coolapk', 'Google', 'Xiaomi'}
    cols_new = {'anzhi': "Anzhi", 'appchina': 'Appchina', 'google': 'Google', 'xiaomi': 'Xiaomi', 'baidu': 'Baidu', 'qihu360': '360', 'coolapk': 'Coolapk'}
    for col, file_prefix in cols_new.items():
        # 连接MobSF的数据库
        mobsf_col = db_conn[mobsf_dbname][col]
        for record in mobsf_col.find({}, no_cursor_timeout=True):
            # 数据库里面有关于这个app的violation数据的话，就进行处理，更新里面的内容
            record_in_squat = violation_col.find_one({"app_name": file_prefix + "_" + record['file_name'][:-4]})
            # record_in_squat = violation_col.find_one({"app_name": record['file_name'][:-4].split("_", 1)[1]})
            # 如果violation数据库中不存在这个app，那么说明这个app的manifest文件缺失
            if not record_in_squat:
                print(
                    "[Cannot find app in violation database], continue. (" + file_prefix + "_" + record['file_name'][
                                                                                                 :-4] + ")")
                continue
            print("[Found in the violation database]: " + file_prefix + "_" + record['file_name'][:-4])
            if 'minInstalls' in record['result']['playstore_details'].keys() and 'genre' in record['result'][
                'playstore_details'].keys():
                installs = record['result']['playstore_details']['minInstalls']
                genre = record['result']['playstore_details']['genre']
                print("[Details get from the original database]: ", record['result']['package_name'])
            elif old_col.find_one({"app_ID": record['file_name'][:-4]}):
                old_record = old_col.find_one({"app_ID": record['file_name'][:-4]})
                if "installs" in old_record.keys() and "genre" in old_record.keys():
                    installs = old_record["installs"]
                    genre = old_record["genre"]
                else:
                    installs = 0
                    genre = 0
            else:
                print("[Crawling installs information] ", record['result']['package_name'])
                # installs, genre = crawl_install_genre(record['result']['package_name'])
                # time.sleep(1)
                # installs = 0
                installs = 0
                genre = 0
            record_id = record_in_squat["_id"]
            if "violations" in record_in_squat.keys():
                updated_violations = record_in_squat["violations"]
            else:
                updated_violations = {}

            if len(record["result"]["android_api"].keys()):
                # i2 uncheckgrant
                if "api_ipc" in record["result"]["android_api"].keys() and "api_check_permission" not in \
                        record["result"]["android_api"].keys():
                    updated_violations["i2"] = 1
                # i3 uncheckdef
                if "api_ipc" in record["result"]["android_api"].keys() and "api_get_certificate" not in \
                        record["result"]["android_api"].keys():
                    updated_violations["i3"] = 1

            violation_col.update_one({"_id": record_id},
                                     {"$set": {"violations": updated_violations, "installs": installs, "genre": genre}})


def updateViolationforNonInvoker(db):
    client = MongoClient()
    col = client[db]['permission']
    for record in col.find():
        is_invoker = 0
        for i in record["requested_permissions"]:
            if not i.startswith("android"):
                if not i.startswith("com.google"):
                    # if i not in record["defined_permissions"]:
                    print(record["app_name"], "has custom permission", i)
                    is_invoker = 1
        if "violations" in record.keys():
            violation = record["violations"]
        else:
            continue
        if not is_invoker:
            if "i1" in violation.keys() and violation["i1"]:
                violation["i1"] = 0
            if "i2" in violation.keys() and violation["i2"]:
                violation["i2"] = 0
            if "i3" in violation.keys() and violation["i3"]:
                violation["i3"] = 0
        # violation["has_custom"] = has_custom
            print("Reset the violations for apps not that is not invoker")
            col.update_one({"_id": record["_id"]}, {"$set": {"violations": violation}})
