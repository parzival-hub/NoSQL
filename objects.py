from enum import Enum

class PostRequestBodyType(Enum):
    JSON = "application/json"
    FORM_URLENCODED = "application/x-www-form-urlencoded"
    MULTIPART_FORM_DATA = "multipart/form-data"
    XML = "application/xml"
    PLAIN_TEXT = "text/plain"

class AttackTarget:
    def __init__(self, url="", action="", method="", parameters=""):
        self.action = action
        self.method = method
        self.parameters = parameters    
        self.url = url  
          

    def __str__(self):
        return f"\n\tUrl: {self.url},\n\tAction: {self.action}, \n\tMethod: {self.method}, \n\tParameter Data: {self.parameters}"
