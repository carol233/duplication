# coding:utf-8
import csv
import hashlib
import os

def getApkList(rootDir, pick_str):
    """
    :param rootDir:  root directory of dataset
    :return: A filepath list of sample
    """
    filePath = []
    for parent, dirnames, filenames in os.walk(rootDir):
        for filename in filenames:
            if pick_str in filename:
                file = parent + "/" + filename
                filePath.append(file)
    return filePath


def getFileList(rootDir):
    """
    :param rootDir:  root directory of dataset
    :return: A filepath list of sample
    """
    filePath = []
    for parent, dirnames, filenames in os.walk(rootDir):
        for filename in filenames:
            file = parent + "/" + filename
            filePath.append(file)
    return filePath


def save_results(output, apk_dict):
    with open(output, "w", newline="") as fw:
        writer = csv.writer(fw)
        writer.writerow(["name", "path"])
        for item in apk_dict:
            writer.writerow([item + ".apk", apk_dict[item]])

def get_md5(s):
    m = hashlib.md5()
    m.update(s.encode('utf-8'))
    return m.hexdigest()


# Exception class to signify an Apktool Exception
class ApkToolException(Exception):
    def __init__(self, command):
        self.command = command

    def __str__(self):
        return repr(self.command)