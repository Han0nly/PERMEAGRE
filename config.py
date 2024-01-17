#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
-------------------------------------------------
@File    : config.py
@Time    : 2021/9/1 4:01 PM
@Author  : Han0nly
@Github  : https://github.com/Han0nly
@Email   : zhangxh@stu.xidian.edu.cn
-------------------------------------------------
"""

# /Volumes/ASMT-MAC/apks/baidu, /Volumes/ASMT-MAC/apks/qihu360, /Volumes/ASMT-MAC/apks/coolapk
apk_dir = "/Volumes/ASMT-MAC/apks/"
result_json_dir = "/Users/zxh/PycharmProjects/PermSquatting/resources/result_files"
manifest_dir = "/Users/zxh/PycharmProjects/PermSquatting/manifest"
temp_dir = "/Users/zxh/PycharmProjects/PermSquatting/resources/tmp"
baksmali = "/Users/zxh/myproject/PermDet-MobSF/mobsf/StaticAnalyzer/tools/baksmali-2.5.2.jar"
JADX_BINARY = "/Users/zxh/myproject/PermDet-MobSF/mobsf/StaticAnalyzer/tools/jadx/bin/jadx"

# ==========ANDROID SKIP CLASSES==========================
# Common third party classes/paths that will be skipped
# during static analysis
SKIP_CLASS_PATH = {
    'com/google/', 'androidx', 'okhttp2/', 'okhttp3/',
    'com/android/', 'com/squareup', 'okhttp/',
    'android/content/', 'com/twitter/', 'twitter4j/',
    'android/support/', 'org/apache/', 'oauth/signpost',
    'android/arch', 'org/chromium/', 'com/facebook',
    'org/spongycastle', 'org/bouncycastle',
    'com/amazon/identity/', 'io/fabric/sdk',
    'com/instabug', 'com/crashlytics/android',
    'kotlinx/', 'kotlin/',
}

# desdir = "manifest"
# filepath = "./"
# 解压文件

system_perms = [
    "andriod.permission.ACCESS_CHECKIN_PROPERTIES",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_NOTIFICATION_POLICY",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.ACCOUNT_MANAGER",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.BATTERY_STATS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_CARRIER_MESSAGING_SERVICE",
    "android.permission.BIND_CARRIER_SERVICES",
    "android.permission.BIND_CHOOSER_TARGET_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_CONDITION_PROVIDER_SERVICE",
    "android.permission.BIND_DREAM_SERVICE",
    "android.permission.BIND_INCALL_SERVICE",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_MIDI_DEVICE_SERVICE",
    "android.permission.BIND_NFC_SERVICE",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_PRINT_SERVICE",
    "android.permission.BIND_QUICK_SETTINGS_TILE",
    "android.permission.BIND_REMOTEVIEWS",
    "android.permission.BIND_SCREENING_SERVICE",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
    "android.permission.BIND_TEXT_SERVICE",
    "android.permission.BIND_TV_INPUT",
    "android.permission.BIND_VOICE_INTERACTION",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_VR_LISTENER_SERVICE",
    "android.permission.BIND_WALLPAPER",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BLUETOOTH_PRIVILEGED",
    "android.permission.BODY_SENSORS",
    "android.permission.BROADCAST_PACKAGE_REMOVED",
    "android.permission.BROADCAST_SMS",
    "android.permission.BROADCAST_STICKY",
    "android.permission.BROADCAST_WAP_PUSH",
    "android.permission.CALL_PHONE",
    "android.permission.CALL_PRIVILEGED",
    "android.permission.CAMERA",
    "android.permission.CAPTURE_AUDIO_OUTPUT",
    "android.permission.CAPTURE_SECURE_VIDEO_OUTPUT",
    "android.permission.CAPTURE_VIDEO_OUTPUT",
    "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
    "android.permission.CHANGE_CONFIGURATION",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.CLEAR_APP_CACHE",
    "android.permission.CONTROL_LOCATION_UPDATES",
    "android.permission.DELETE_CACHE_FILES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.DIAGNOSTIC",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.DUMP",
    "android.permission.EXPAND_STATUS_BAR",
    "android.permission.FACTORY_TEST",
    "android.permission.GET_ACCOUNTS",
    "android.permission.GET_ACCOUNTS_PRIVILEGED",
    "android.permission.GET_PACKAGE_SIZE",
    "android.permission.GET_TASKS",
    "android.permission.GLOBAL_SEARCH",
    "android.permission.INSTALL_LOCATION_PROVIDER",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.INSTALL_SHORTCUT",
    "android.permission.INTERNET",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.LOCATION_HARDWARE",
    "android.permission.MANAGE_DOCUMENTS",
    "android.permission.MASTER_CLEAR",
    "android.permission.MEDIA_CONTENT_CONTROL",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.MODIFY_PHONE_STATE",
    "android.permission.MOUNT_FORMAT_FILESYSTEMS",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.NFC",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.PERSISTENT_ACTIVITY",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_FRAME_BUFFER",
    "android.permission.READ_INPUT_STATE",
    "android.permission.READ_LOGS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.READ_SYNC_SETTINGS",
    "android.permission.READ_SYNC_STATS",
    "android.permission.READ_VOICEMAIL",
    "android.permission.REBOOT",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.REORDER_TASKS",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.RESTART_PACKAGES",
    "android.permission.SEND_RESPOND_VIA_MESSAGE",
    "android.permission.SEND_SMS",
    "android.permission.SET_ALARM",
    "android.permission.SET_ALWAYS_FINISH",
    "android.permission.SET_ANIMATION_SCALE",
    "android.permission.SET_DEBUG_APP",
    "android.permission.SET_PREFERRED_APPLICATIONS",
    "android.permission.SET_PROCESS_LIMIT",
    "android.permission.SET_TIME",
    "android.permission.SET_TIME_ZONE",
    "android.permission.SET_WALLPAPER",
    "android.permission.SET_WALLPAPER_HINTS",
    "android.permission.SIGNAL_PERSISTENT_PROCESSES",
    "android.permission.STATUS_BAR",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.TRANSMIT_IR",
    "android.permission.UNINSTALL_SHORTCUT",
    "android.permission.UPDATE_DEVICE_STATS",
    "android.permission.USE_FINGERPRINT",
    "android.permission.USE_SIP",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.WRITE_APN_SETTINGS",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.WRITE_GSERVICES",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.WRITE_SETTINGS",
    "android.permission.WRITE_SYNC_SETTINGS",
    "android.permission.WRITE_VOICEMAIL",
]

firebase_perms = [
    "com.google.firebase.iid.FirebaseInstanceIdReceiver",
    "com.google.android.c2dm.permission.SEND",
]