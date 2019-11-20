# coding:utf-8
import csv

from common import *
import json
import re
import os
import subprocess
import threading
import shutil
import threadpool

class Api_analyzer:
    def __init__(self, OPTIONS):
        self.OPTIONS = OPTIONS
        self.num_dic = {}
        self.api_hash = {}
        self.apk_select = {}
        self.lock = threading.Lock()
        self.max_jobs = 5
        self.all = 0
        self.nodup = 0
        self.dup = 0
        self.error = 0
        self.p = re.compile(r'Landroid/.*?\(|Ljava/.*?\(')
        self.find_file = re.compile(r'.smali$')
        self.frametemp = "frametemp/"

    def get_number(self, s):
        if s not in self.num_dic:
            self.num_dic[s] = len(self.num_dic)
        return str(self.num_dic[s])

    def processone(self, apk_path):
        apkname = os.path.split(apk_path)[-1][:-4]
        print("[+] Analyzing " + apkname)

        cmd = self.OPTIONS.apktool + " d " + apk_path + " -o " + \
              os.path.join(self.OPTIONS.tmp, apkname + ".out") + " -p " + self.frametemp
        output = os.system(cmd)
        if output != 0:
            self.lock.acquire()
            self.error += 1
            self.lock.release()
            raise ApkToolException(cmd)

        path = self.OPTIONS.tmp + '/' + apkname + '.out' + '/smali'
        APKOUTPUT = os.path.join(self.OPTIONS.tmp, apkname + '.out')

        if not os.path.exists(path):
            shutil.rmtree(APKOUTPUT)
            return
        try:
            # print path
            all_thing = getFileList(path)
            this_call_num = 0
            this_dict = {}
            for thing in all_thing:
                try:
                    if not self.find_file.search(thing):
                        continue
                    f = open(thing, 'r')
                    for u in f:
                        match = self.p.findall(u)
                        for syscall in match:
                            this_call_num += 1
                            call_num = self.get_number(syscall)
                            if call_num in this_dict:
                                this_dict[call_num] += 1
                            else:
                                this_dict[call_num] = 1
                    f.close()
                except:
                    print('Can\'t open   ' + thing)

            logs = ['Landroid/util/Log;->v(', 'Landroid/util/Log;->e(', 'Landroid/util/Log;->w(',
                    'Landroid/util/Log;->i(',
                    'Landroid/util/Log;->d(']
            for log in logs:
                if self.get_number(log) in this_dict:
                    del this_dict[self.get_number(log)]
            if len(this_dict) == 0:
                shutil.rmtree(APKOUTPUT)
                return
            api_dict_str = str(json.dumps(this_dict))
            api_dict_md5 = get_md5(api_dict_str)

            # save
            self.lock.acquire()
            if api_dict_md5 in self.api_hash:
                self.dup += 1
            else:
                self.api_hash[api_dict_md5] = 1
                self.apk_select[apkname] = apk_path
                self.nodup += 1
            self.lock.release()

            shutil.rmtree(APKOUTPUT)

        except Exception as e:
            print(e, apk_path)
            if os.path.exists(APKOUTPUT):
                shutil.rmtree(APKOUTPUT)
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
        print("[+] API call analysis error " + str(self.error))
        print("[+] Saving results to " + self.OPTIONS.output)
        save_results(self.OPTIONS.output, self.apk_select)