import random
import string
from bs4 import BeautifulSoup
import requests
from urllib.parse import quote, urlparse
import sys
from objects import *

# webrequest utils
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
        host = parsed_url.hostname,
        port=parsed_url.port,
        path=form.get('action', ''),
        request_body_type=PostRequestBodyType.FORM_URLENCODED
    )
    
    if not attack_target.http_verb:
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

def get_random_payload_response(attack_target,debug=False):        
    default_response = send_post_request(attack_target, generate_random_string(8),debug=debug)
    if not default_response:
        raise Exception(f"Default Response failed: {default_response.status_code}, {default_response.text}")
    return default_response

def send_extraction_request(attack_target, extraction_point, extraction_payload,debug = False):
    # create payload by replacing injection point 
    if isinstance(extraction_point, dict):
        payload = extraction_point.copy()
        for inject_type in ["§inject§", "§regex_brute§"]:
            # find key of inject_type value 
            matching_keys = find_keys_of_dict_values(payload, inject_type)
            if matching_keys:
                payload[matching_keys[0]] = payload[matching_keys[0]].replace(inject_type, extraction_payload)
                continue

    elif isinstance(extraction_point, str):
        payload = extraction_point
        for inject_type in ["§inject§", "§regex_brute§"]:
            payload = payload.replace(inject_type, extraction_payload)        
    else:
        raise Exception(f"Unhandled extraction_point type: {type(extraction_point)}")
    
    response = send_post_request(attack_target, payload,debug=debug)
    if response == None:
        raise Exception("Extraction response is None")
    res = len(response.text) != len(attack_target.baseline_response.text)
    if debug:
        print(attack_target.get_target_url(), payload, res)
    return res

def send_post_request(attack_target, payload, debug = False):
    r_body_type = attack_target.request_body_type
    
    if r_body_type == PostRequestBodyType.JSON:
        r_data = attack_target.parameters.copy()
        r_data[attack_target.scan_param_name] = payload
        
        if debug:
            print(attack_target.get_target_url(), r_data)            
        r = requests.post(
            attack_target.get_target_url(),
            headers=attack_target.headers,
            cookies=attack_target.cookies,
            json=r_data,
        )    
    
    elif r_body_type == PostRequestBodyType.FORM_URLENCODED:
        r_data = attack_target.parameters.replace(f"§{attack_target.scan_param_name}§", quote(payload))
        if debug:
            print(attack_target.get_target_url(), r_data)            
        r = requests.post(
            attack_target.get_target_url(),
            headers=attack_target.headers,
            cookies=attack_target.cookies,
            data=r_data,
        )    
    else:
        raise Exception(f"The request_body_type '{r_body_type}' can not be handled in this version.")
    
    
    if r and debug:
        print(len(r.text), r.status_code, r.text)
    return r
    
# String and check utils
def remove_char_at_index(s, index):
    if index < 0 or index >= len(s):
        raise IndexError("Index out of range")
    return s[:index] + s[index + 1:]

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

def find_keys_of_dict_values(pdict, pvalue):
    return [key for key, value in pdict.items() if pvalue in value]
# UI
def print_results(found_attributes, results):
    print("Extracted attributes:")
    for attr, length in found_attributes:
        print(f"[+]  {attr}:{length}")
    print("Extracted data:")
    for r in results:
        print(f"[+] {r[0]}:{r[1]}")

def progress_bar(progress, total, bar_length=40):
    percent = float(progress) / total
    arrow = '=' * int(round(percent * bar_length) - 1) + '>'
    spaces = ' ' * (bar_length - len(arrow))
    
    sys.stdout.write(f"\rProgress: [{arrow}{spaces}] {int(percent * 100)}%")
    sys.stdout.flush()
    
    if progress == total:        
        print()
