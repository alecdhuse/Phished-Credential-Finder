import datetime
import json
import os
import re
import requests
import time

from ipaddress import ip_network, ip_address

def find_cred_files(base_url, dump_file_names):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    }

    possible_cred_files = []

    for dump_file in dump_file_names:
        url = base_url + dump_file

        try:
            head_response = requests.head(url, headers=headers, timeout=0.5)

            if head_response.status_code == 200:
                response = requests.get(url, headers=headers, timeout=2.0)
                content_type = head_response.headers['content-type']
                content_len = head_response.headers['content-length']

                if ("<!DOCTYPE html" in response.text or
                    response.text.strip().startswith("<!doctype html") or
                    response.text.strip().startswith("<html") or
                    response.text.strip().startswith("<!-- pageok -->") or
                    response.text.strip().startswith("<?php") or
                    response.text.strip().startswith("<?xml") or
                    content_type.startswith("text/html")):
                    # HTML page
                    continue
                elif content_type.startswith("image/"):
                    # Image file
                    continue
                elif len(response.text) > 3:
                    print ("-------")
                    print (url)
                    print (content_type)
                    print (content_len)
                    print ("--")
                    print (response.text)

                    possible_cred_files.push({"data": response.text, "url": url})
        except Exception as err:
            continue
            print("Error looking for drop file: %s" % str(err))

    return possible_cred_files

def get_base_url(url):
    if len(url) > 1:
        if url.endswith("/"):
            base_url = url
        else:
            base_test = url.rsplit('/',1)[0]

            if (base_test == "https://" or base_test == "http://"):
                base_url = url + "/"
            else:
                base_url = base_test + "/"

    return base_url

def get_new_phish_urls(data_sources):
    reported_urls = []
    line_number = 0

    try:
        for data_source in data_sources:
            response = requests.get(data_source['url'], headers=data_source['headers'], data=data_source['parameters'])

            if data_source['data_type'] == "json":
                json_response = json.loads(response.text)

                if (json_response['result_code'] > 0):
                    for result in json_response["result"]:
                        reported_urls.append([line_number, result["url"]])
                        line_number += 1
                else:
                    print (json.dumps(json_response))

            else:
                for line in response.text.split("\n"):
                    if data_source['data_type'] == "csv":
                        data_elements = line.split(",")

                        for data_element in data_elements:
                            if data_element.lower().startswith("http"):
                                reported_urls.append(data_element)
                                break

                    elif data_source['data_type'] == "text":
                        reported_urls.append([line_number, line])

                    line_number += 1

                if data_source['data_type'] == "csv":
                    #fist line is field info, remove it
                    reported_urls.pop(0)

                #Last line will often be incomplete, remove it.
                reported_urls[:-1]
    except Exception as err:
        raise Exception("Error getting new urls: %s" % str(err))

    return reported_urls

def load_settings_file(file_path):
    try:
        with open(file_path) as json_file:
            data = json.load(json_file)
            return data
    except Exception as err:
        print("Error loading settings file: %s" % str(err))
        return {}

def main():
    settings_path  = os.path.dirname(os.path.realpath(__file__)) + os.path.sep
    settings_path += "settings.json"
    settings = load_settings_file(settings_path)

    reported_urls = get_new_phish_urls(settings['data_sources'])

    for reported_url in reported_urls:
        base_url = get_base_url(reported_url)
        possible_cred_files = find_cred_files(base_url, settings['credential_file_names'])

        for possible_cred_file in possible_cred_files:
            print (possible_cred_file)

main()
