# coding:utf-8
import csv
import zipfile

from common import *
import hashlib
import os
import threading
import threadpool

class Dex_analyzer:
    def __init__(self, OPTIONS):
        self.OPTIONS = OPTIONS
        self.dex_hash = {}
        self.apk_select = {}
        self.lock = threading.Lock()
        self.max_jobs = 5
        self.all = 0
        self.nodup = 0
        self.dup = 0
        self.error = 0

    def processone(self, apk):
        apk_sha256 = os.path.split(apk)[-1][:-4]
        print("[+] Analyzing " + apk_sha256)
        try:
            # DEX MD5
            dex_md5 = "None"
            z = zipfile.ZipFile(apk)
            if "classes.dex" in z.namelist():
                dex_item = z.open("classes.dex", 'r')
                dex_md5 = hashlib.md5(dex_item.read()).hexdigest()
            z.close()

            self.lock.acquire()
            if not dex_md5 == "None":
                if dex_md5 in self.dex_hash:
                    self.dup += 1
                else:
                    # cp
                    self.apk_select[apk_sha256] = apk
                    self.dex_hash[dex_md5] = 1
                    self.nodup += 1
            else:
                self.error += 1
            self.lock.release()

        except Exception as e:
            print(e, apk)
            return None

    def start(self):
        apks = getApkList(self.OPTIONS.input, ".apk")
        self.all = len(apks)

        args = [(apk) for apk in apks]
        pool = threadpool.ThreadPool(self.max_jobs)
        requests = threadpool.makeRequests(self.processone, args)
        [pool.putRequest(req) for req in requests]
        pool.wait()

        print("[+] Total apks ", self.all)
        print("[+] Samples without duplication totally " + str(self.nodup))
        print("[+] Samples with duplication totally " + str(self.dup))
        print("[+] Dex analysis error " + str(self.error))
        print("[+] Saving results to " + self.OPTIONS.output)
        save_results(self.OPTIONS.output, self.apk_select)
