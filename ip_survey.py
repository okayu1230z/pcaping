#!/usr/bin/python3
# coding : UTF-8

#TOKEN = "c4d9d9b77a832d"

import os
import sys
import time
import requests

def touch(path):
    f = open(path, 'w')
    f.close()

def main():
    args = sys.argv

    # this is simple argument check, please refactor.
    if "ip_survey.py" not in args[-1]:
        filename = args[1]
        base = os.path.splitext(os.path.basename(filename))[0]
        output_log = base + "_service.log"
    else:
        print('** pcap_analysis.py wants argment')
        return

    with open(filename) as f:
        ip_service_list = f.readlines()

    touch(output_log)

    ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36'
    headers = {'User-Agent': ua}

    for isl in ip_service_list:
        url = "https://ipinfo.io/" + isl.split(':')[0]
        response = requests.get(url, headers=headers, allow_redirects=False)
        full = response.text
        if "Organization" in full:
            print(response.text.split('Organization')[1].split("\n")[2].strip())
            tmp = str(isl).split('\n')[0]
            isl = tmp + ":" + response.text.split('Organization')[1].split("\n")[2].strip() + "\n"
        with open(output_log, mode='a') as f:
            f.write(isl)

if __name__ == "__main__":
    main()
