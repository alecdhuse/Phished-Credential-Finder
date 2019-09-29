import datetime
import json
import os
import re
import requests
import time

from ipaddress import ip_network, ip_address

def extract_ip_addresses(input):
    ips = re.findall(r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$|^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*', input)

    return ips

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
                    possible_cred_files.push({"data": response.text, "url": url})
        except Exception as err:
            continue
            print("Error looking for drop file: %s" % str(err))

    return possible_cred_files

def fire_alert(alert_title, match_data, cred_file):
    # Replace with your custom code
    print (alert_title)
    print (match_data)
    print (cred_file)

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
                        reported_urls.append(result["url"])
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
                        reported_urls.append(line)

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

def string_search(search_file, search_strings, chars_to_grab):
    found_text = []

    for search_string in search_strings:
        found_index = search_file.indexOf(search_strings)

        while (found_index >= 0):
            found_index = search_file.indexOf(search_strings)
            grab_start = (found_index - chars_to_grab) if (found_index - chars_to_grab) >= 0 else 0
            grab_end = (found_index + chars_to_grab) if (found_index + chars_to_grab) < len(search_file) else len(search_file)
            grab_text = search_file[grab_start: grab_end]
            found_text.append(grab_text)

    return found_text

def main():
    settings_path  = os.path.dirname(os.path.realpath(__file__)) + os.path.sep
    settings_path += "settings.json"
    settings = load_settings_file(settings_path)

    reported_urls = get_new_phish_urls(settings['data_sources'])

    for reported_url in reported_urls:
        base_url = get_base_url(reported_url)
        possible_cred_files = find_cred_files(base_url, settings['credential_file_names'])

        for possible_cred_file in possible_cred_files:
            print(possible_cred_file['data'])

            # String Search
            string_matches = string_search(possible_cred_file['data'], settings['search_data']['string_match'], 50)

            for string_match in string_matches:
                fire_alert("String Match", string_match, possible_cred_file)

            #IP search
            extracted_ips = extract_ip_addresses(possible_cred_file['data'])

            for ip in extracted_ips:
                for cider_network in settings['search_data']['cider_subnets']:
                    network = ip_network(cider_network)

                    if (ip in network):
                        # IP found
                        fire_alert("IP Match", ip, possible_cred_file)
main()
