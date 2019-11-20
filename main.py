# coding:utf-8
import os
import sys
import argparse
from dex_analyzer import Dex_analyzer
from opcode_analyzer import Opseq_analyzer
from apicall_analyzer import Api_analyzer


def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-i", "--input", metavar="D:/genomeapps/samples/", help="Your dataset path.")
    parser.add_argument("-o", "--output", default="output.csv", metavar="xxx.csv", help="Your destination output file.")
    parser.add_argument("-f", "--filter", choices=["d", "o", "a"], help="Dex, Opcode sequence, or API call.")
    parser.add_argument("-a", "--apktool", default="apktool", help="Your ApkTool path.")
    parser.add_argument("-t", "--tmp", default="TMP", help="Tmp path.")
    parser.add_argument("-l", "--logging", default="LOG", help="Logging path.")
    parser.add_argument("-m", "--maxjob", type=int, default=5, help="Max job of threadpool.")
    options = parser.parse_args(args)
    return options

if __name__ == '__main__':

    OPTIONS = getOptions()
    # replace "\\" and "\" to "/"
    OPTIONS.input = OPTIONS.input.replace("\\\\", "/")
    OPTIONS.input = OPTIONS.input.replace("\\", "/")
    OPTIONS.apktool = OPTIONS.apktool.replace("\\\\", "/")
    OPTIONS.apktool = OPTIONS.apktool.replace("\\", "/")
    if not OPTIONS.input.endswith("/"):
        OPTIONS.input += "/"

    if not os.path.exists(OPTIONS.tmp):
        os.mkdir(OPTIONS.tmp)
    if not os.path.exists(OPTIONS.logging):
        os.mkdir(OPTIONS.logging)
    if OPTIONS.filter == "d":
        Dex_analyzer(OPTIONS).start()
        print("[+] Starting removing dex duplication...")
    elif OPTIONS.filter == "o":
        Opseq_analyzer(OPTIONS).start()
        print("[+] Starting removing opcode sequence duplication...")
    elif OPTIONS.filter == "a":
        Api_analyzer(OPTIONS).start()
        print("[+] Starting removing api call duplication...")

    print("[^_^] Done.")
