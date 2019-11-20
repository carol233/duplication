# coding:utf-8
import logging

from common import *
import os
import subprocess
import threading
import shutil
import threadpool

class Opseq_analyzer:
    def __init__(self, OPTIONS):
        self.OPTIONS = OPTIONS
        self.opseq_hash = {}
        self.apk_select = {}
        self.lock = threading.Lock()
        self.max_jobs = 5
        self.all = 0
        self.nodup = 0
        self.dup = 0
        self.error = 0

    def apktool_decode_apk(self, apk_file, out_file, include_libs):
        '''
        :param apk_file: he whole path of apk file (include file name)
        :param out_file: path/decodefile.smail     (the decode file path)
        :param include_libs: None
        :return:
        '''
        # Runs the apktool on a given apk
        apktoolcmd = "{0} d -f {1} -o {2}".format(self.OPTIONS.apktool, apk_file, out_file)

        '''
        command example
        /usr/local/bin/apktool d -f small_proto_apks/malware/gen10_0e187773-d465-400f-942f-f95e52767222_app-release.apk -o decode_data/gen10_0e187773-d465-400f-942f-f95e52767222_app-release.apk.smali
        '''
        output = os.system(apktoolcmd)
        if output != 0: raise ApkToolException(apktoolcmd)

        # Checks if we should keep the smali files belonging to the android support libraries
        if not include_libs:
            # Don't keep the smali/android folder
            android_folder = os.path.join(out_file, "smali/android")
            if os.path.exists(android_folder):
                rm_cmd = "rm -r %s" % (android_folder)
                os.system(rm_cmd)

    def get_opcode_seq(self, smali_fname, dalvik_opcodes):
        # Returns opcode sequence created from smali file 'smali_fname'.
        '''
        :param smali_fname: the smali file path
        :param dalvik_opcodes: the opcode dict
        :return:
        '''
        opcode_seq = ""

        with open(smali_fname, mode="r") as bigfile:
            reader = bigfile.read()
            for i, part in enumerate(reader.split(".method")):
                add_newline = False
                if i != 0:
                    method_part = part.split(".end method")[0]
                    method_body = method_part.strip().split('\n')
                    for line in method_body:
                        line1 = line.strip()
                        if not line1.startswith('.') and not line1.startswith('#') and line1:
                            method_line = line1.split()
                            if method_line[0] in dalvik_opcodes:
                                add_newline = True
                                opcode_seq += dalvik_opcodes[method_line[0]]
                    if add_newline:
                        opcode_seq += '\n'
        return opcode_seq

    def decode_application(self, apk_file_location, tmp_file_directory, hash, include_libs):
        # Decodes the apk at apk_file_location and
        # stores the decoded folders in tmp_file_directory
        '''
        :param apk_file_location: the whole path of apk file (include file name)
        :param tmp_file_directory: the path of decode file location
        :param hash: the apk file name
        :param include_libs: None
        :return: the path of .smali file
        '''
        out_file_location = os.path.join(tmp_file_directory, hash + ".smali")
        try:
            self.apktool_decode_apk(apk_file_location, out_file_location, include_libs)
        except ApkToolException:
            logging.error("ApktoolException on decoding apk  {0} ".format(apk_file_location))
            pass
        return out_file_location

    def create_opcode_seq(self, decoded_dir):
        # Returns true if creating opcode sequence file was successful,
        # searches all files in smali folder,
        # writes the coresponding opcode sequence to a .opseq file
        # and depending on the include_lib value,
        # it includes or excludes the support library files
        '''
           :param decoded_dir : the path of .smali file
           :param opseq_file_directory : the dict
           :param apk_hash : the apk file name
        '''
        dalvik_opcodes = {}
        # Reading Davlik opcodes into a dictionary
        with open("DalvikOpcodes.txt") as fop:
            for linee in fop:
                (key, val) = linee.split()
                dalvik_opcodes[key] = val
        try:
            smali_dir = os.path.join(decoded_dir, "smali")
            opseq = ""
            for root, dirs, fnames in os.walk(smali_dir):
                for fname in fnames:
                    full_path = os.path.join(root, fname)
                    tmp = self.get_opcode_seq(full_path, dalvik_opcodes)
                    opseq += tmp
            if opseq:
                opseqhash = get_md5(opseq)
                return opseqhash
            else:
                return None
        except Exception as e:
            logging.error('Exception occured during opseq creation {0}'.format(str(e)))
            return None

    def processone(self, apk):
        apk_file_location = apk
        apk_hash = os.path.split(apk_file_location)[-1][:-4]
        print("[+] Analyzing " + apk_hash)
        try:
            decoded_location = self.decode_application(apk_file_location, self.OPTIONS.tmp, apk_hash, False)
            if not os.path.exists(decoded_location) or not os.listdir(decoded_location):
                logging.error('NOT decoded directory: {0}'.format(apk_file_location))
                return

            result = self.create_opcode_seq(decoded_location)
            '''
               decode_location : the path of .smali file
               opseq_file_directory : the dict
               apk_hash : the apk file name
            '''
            self.lock.acquire()
            if result:
                if result in self.opseq_hash:
                    self.dup += 1
                else:
                    self.nodup += 1
                    self.apk_select[apk_hash] = apk_file_location
            else:
                logging.error("opseq file creation error!")
                self.error += 1
            self.lock.release()

            if os.path.exists(decoded_location):
                shutil.rmtree(decoded_location)

        except Exception as e:
            print(e, apk_file_location)
            return None

    def start(self):
        logging.basicConfig(filename=self.OPTIONS.logging + "/opseq.log", level=logging.DEBUG)
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
        print("[+] Opcode sequence analysis error " + str(self.error))
        print("[+] Saving results to " + self.OPTIONS.output)
        save_results(self.OPTIONS.output, self.apk_select)
