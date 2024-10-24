import json
import base64
from objects import *

import xml.etree.ElementTree as ET

def parse_burp_request(file_path):
    with open(file_path, "r") as f:
        root = ET.fromstring(f.read())

    first_item = root.find('item')
    
    return {
        "burp_version": root.attrib.get("burpVersion"),
        "export_time": root.attrib.get("exportTime"),
        "time": first_item.find('time').text,
        "url": first_item.find('url').text,
        "host": first_item.find('host').text,
        "host_ip": first_item.find('host').attrib.get('ip'),
        "port": first_item.find('port').text,
        "protocol": first_item.find('protocol').text,
        "method": first_item.find('method').text,
        "path": first_item.find('path').text,
        "extension": first_item.find('extension').text,
        "request_base64": first_item.find('request').attrib.get('base64'),
        "request_data": first_item.find('request').text,
        "status": first_item.find('status').text,
        "responselength": first_item.find('responselength').text,
        "mimetype": first_item.find('mimetype').text,
        "response_base64": first_item.find('response').attrib.get('base64'),
        "response_data": first_item.find('response').text,
        "comment": first_item.find('comment').text if first_item.find('comment') is not None else ""
    }

def extract_headers_and_cookies(request_data):
    """
    Extract headers and cookies from the raw request data.
    Cookies are found in the 'Cookie' header.
    """
    headers = {}
    cookies = {}
    
    # Split the request data by lines
    lines = request_data.splitlines()
    
    # Loop through the lines to extract headers
    for line in lines:
        if ": " in line:
            # This is a header line
            key, value = line.split(": ", 1)
            headers[key] = value

            # If the header is 'Cookie', extract cookies
            if key.lower() == "cookie":
                # Parse the cookies; they are usually key=value pairs separated by '; '
                cookie_pairs = value.split("; ")
                for pair in cookie_pairs:
                    cookie_key, cookie_value = pair.split("=", 1)
                    cookies[cookie_key] = cookie_value
        
        # Stop at the first empty line (end of headers)
        if line.strip() == "":
            break

    return headers, cookies

def decode_base64(encoded_data):
    """Helper function to decode Base64-encoded data"""
    return base64.b64decode(encoded_data).decode('utf-8')

def extract_content_type(request_data):
    """Extract the content type from the request headers"""
    headers = request_data.split('\n')
    for header in headers:
        if header.lower().startswith("content-type:"):
            return header.split(":")[1].strip()
    return None

def map_content_type_to_enum(content_type):
    """Map the content type string to the appropriate PostRequestBodyType"""
    if PostRequestBodyType.JSON.value in content_type:
        return PostRequestBodyType.JSON
    elif PostRequestBodyType.FORM_URLENCODED.value in content_type:
        return PostRequestBodyType.FORM_URLENCODED
    elif PostRequestBodyType.MULTIPART_FORM_DATA.value in content_type:
        return PostRequestBodyType.MULTIPART_FORM_DATA
    elif PostRequestBodyType.XML.value in content_type:
        return PostRequestBodyType.XML
    elif PostRequestBodyType.PLAIN_TEXT.value in content_type:
        return PostRequestBodyType.PLAIN_TEXT
    else:
        return PostRequestBodyType.UNKNOWN


def extract_body_from_request(request_data):
    """
    Extract the body of the request from the raw request data.
    Looks for an empty line to separate headers from the body.
    """
    # Split by lines
    lines = request_data.splitlines()
    
    # Find the index of the first empty line, which separates headers from body
    for i, line in enumerate(lines):
        if line.strip() == "":
            # The body starts after the empty line
            return "\n".join(lines[i+1:])
    
    # If no empty line is found, return an empty body or handle accordingly
    return ""

def create_attack_target_from_burp_data(file_path):
    print(f"[*] Reading Burp File: {file_path}")
    
    try:
        parsed_data = parse_burp_request(file_path)
    except:
        print(f"[-] File {file_path} not found\n")
        exit()
    

    """Create an AttackTarget object from Burp XML data"""
    host = parsed_data["host"]
    http_verb = parsed_data["method"]
    request_data_base64 = parsed_data["request_data"]
    http_schema = parsed_data["protocol"]
    path = parsed_data["path"]
    port = parsed_data["port"]    

    # Decode the Base64-encoded request data
    decoded_request_data = decode_base64(request_data_base64)
    
    # extract headers and cookie
    headers, cookies = extract_headers_and_cookies(decoded_request_data)
    
    # Extract the content type from the request headers
    content_type = extract_content_type(decoded_request_data)
    
    # Determine the PostRequestBodyType based on content type
    request_body_type = map_content_type_to_enum(content_type) if content_type else PostRequestBodyType.UNKNOWN
    
    # Assume the parameters are the body of the request (this can be customized)
    parameters = extract_body_from_request(decoded_request_data)
        
    if request_body_type == PostRequestBodyType.JSON:
        try:
            # Try to parse the parameters as JSON
            parameters = json.loads(parameters)
            if parameters:
                scan_p_name = next(iter(parameters.keys()))
        except json.JSONDecodeError:            
            raise Exception("Encountered JSON request type but parameters are not in valid JSON format")
    elif request_body_type == PostRequestBodyType.FORM_URLENCODED:
        if parameters:
            scan_p_name = parameters.split("=")[0]
    else:
        raise Exception(f"The request_body_type '{request_body_type}' can not be handled in this version.")    
    
    # Create and return the AttackTarget object
    attack_target = AttackTarget(http_verb=http_verb, http_schema=http_schema,host=host,port=port, path=path,  parameters=parameters, request_body_type=request_body_type, headers=headers, cookies=cookies, scan_param_name=scan_p_name)
    return attack_target
