#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
-------------------------------------------------
@File    : defined_permissions.py
@Time    : 15/5/23 11:39 am
@Author  : Han0nly
@Github  : https://github.com/Han0nly
@Email   : zhangxh@stu.xidian.edu.cn
-------------------------------------------------
"""
import argparse

from pymongo import MongoClient


if __name__ == '__main__':
    stores = {"Anzhi": 9972, 'Appchina': 9934, 'Google': 44059, 'Xiaomi': 9966, 'Baidu': 2326, '360': 4241, 'Coolapk': 2587}
    client = MongoClient()
    col = client["permigredb"]['permission']
    count = 0
    # 统计每个定义的权限被定义的次数
    defined_perms = {}
    # 统计权限被使用的次数
    req_perms = {}
    sig_count = 0
    norm_count = 0
    danger_count = 0
    # 统计不同商店对于权限的定义数量
    stores_defined = {}
    # 统计不同商店对于权限的申请数量
    stores_requested = {}
    for i in stores.keys():
        stores_defined[i] = []
        stores_requested[i] = []

    # 统计不同权限级别的自定义权限
    for item in col.find():
        count = count + 1
        if "defined_permissions" in item.keys():
            for perm in item["defined_permissions"].keys():
                if perm in defined_perms.keys():
                    defined_perms[perm] = defined_perms[perm] + 1
                else:
                    defined_perms[perm] = 1
                    if item["defined_permissions"][perm] == "signature" or item["defined_permissions"][perm] == "signatureOrSystem":
                        sig_count = sig_count + 1
                    if item["defined_permissions"][perm] == "normal":
                        norm_count = norm_count + 1
                    if item["defined_permissions"][perm] == "dangerous":
                        danger_count = danger_count + 1
                if perm not in stores_defined[item["app_name"].split("_")[0]]:
                    stores_defined[item["app_name"].split("_")[0]].append(perm)

        if "requested_permissions" in item.keys():
            for perm in item["requested_permissions"]:
                if perm in req_perms.keys():
                    req_perms[perm] = req_perms[perm] + 1
                else:
                    req_perms[perm] = 1
                if perm not in stores_requested[item["app_name"].split("_")[0]]:
                    stores_requested[item["app_name"].split("_")[0]].append(perm)

    print("All defined permissions count:", len(defined_perms.keys()))
    print("All requested permissions count:", len(req_perms.keys()))
    print("Normal permission count:",norm_count)
    print("Dangerous permission count:",danger_count)
    print("Signature permission count:",sig_count)
    print("Permissions definition count:")
    for i in stores.keys():
        print(i)
        print(len(stores_defined[i]), len(stores_defined[i])/stores[i])
    print("Permissions request count:")
    for i in stores.keys():
        print(i)
        print(len(stores_requested[i]), len(stores_requested[i])/stores[i])

    # print("All defined permissions:", sorted(defined_perms.items(), key=lambda x:x[1], reverse=True))
    # print("All request permissions:", sorted(req_perms.items(), key=lambda x:x[1], reverse=True))
