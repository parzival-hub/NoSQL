from enum import Enum

class PostRequestBodyType(Enum):
    JSON = "application/json"
    FORM_URLENCODED = "application/x-www-form-urlencoded"
    MULTIPART_FORM_DATA = "multipart/form-data"
    XML = "application/xml"
    PLAIN_TEXT = "text/plain"
    UNKNOWN = "unknown"  # For cases where we can't determine the content type

class AttackTarget:
    def __init__(self,http_verb="", http_schema="",host="",port="", path="",  parameters="", request_body_type=PostRequestBodyType.UNKNOWN, scan_param_name="", proxies={}, headers={}, cookies={}):
        self.http_verb = http_verb
        self.http_schema = http_schema
        self.host = host
        self.port = str(port)
        self.path = path
        self.parameters = parameters    
        self.request_body_type = request_body_type  # New field to store the request body type
        self.baseline_response = ""
        self.cookies= cookies
        self.headers = headers
        self.scan_param_name = scan_param_name
        self.proxies = proxies

    def __str__(self):
        return (            
            f"Target: {self.http_verb} {self.get_target_url()}\n"            
            f"Parameters: {self.parameters}\n"
            f"Request Body Type: {self.request_body_type.value}\n"
        )

    def set_baseline_response(self, baseline_response):
        self.baseline_response = baseline_response

    def get_target_url(self):
        return self.http_schema+"://"+self.host+":"+self.port+self.path