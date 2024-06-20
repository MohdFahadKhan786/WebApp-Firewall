import re
import requests
from flask import Flask,request,Response
from bs4 import BeautifulSoup
import urllib.parse 


app = Flask(__name__)

# Attack Patterns 
sql_injection_patterns = [
    r"'(?:\s*OR\s*1\s*=\s*1\s*--|OR\s*1\s*=\s*1\s*--)",
    r'\bSELECT\b.*\b(?:(?!)\b(OR|AND)\b)\s+.\b1=1\b.',  
    r'\bUNION\b.*SELECT\b', 
    r'SUBSTRING\s*\(',  
    r'SLEEP\s*\(', r'BENCHMARK\s*\(',  
    r"((\%3D)|(=))[^\n]*((\%27)|(\%3B)|(;))", 
    r"w*((%27)|(\'))((%6F)|o|O)((%72)|r|R)",  
    r"w*((%27)|(\'))((%41)|a|A)((%4E)|n|N)((%44)|d|D)",  
    r"\bUNION\b.SELECT\b.\bFROM\b",  
    r"\bSELECT\b.*\bINTO\b",
    r"(?:(union(.*?)select))",  
    r"having|benchmark|sleep|waitfor",
]
xss_patterns = [
    r'<script\b[^<](?:(?!<\/script>)<[^<])*<\/script>',
    r"<[^>]+ on\w+=(['\"])?[^'\"]*\1?",
    r"<img[^>]\s+src\s=[\s'\"]*javascript:", 
    r"<[^>]+ on\w+\s*=",                            # Broader event handler pattern
    r"<img[^>]\s+src\s=[\s'\"]?\s*[^>]*>",        # Catching more generic <img> tags 
     r"<(|\/|[^\/>][^>]+|\/[^>][^>]+)>",             # Basic tag structure
    r"(alert|prompt|confirm)",                      # JavaScript functions
    r"(onload|onerror|onfocus|onmouseover)=[^'\"]*",  # Event handlers
    r"<script\b[^>]>[^>]?alert\b.*?<\/script>",         # Embedded alerts 
    r"javascript:[^\"\']*" ,
    r'<script\b[^<](?:(?!<\/script>)<[^<])*<\/script>', 
    r"<[^>]+ on(error|click|load|mouseover|submit|change|focus|blur|dblclick|keydown|keypress)=\s*(['\"])?[^'\"]*\2?",
    r"<img[^>]\s+src\s=[\s'\"]*javascript:", 
    r"<[^>]+ on\w+\s*=",  
    r"<img[^>]\s+src\s=[\s'\"]?\s*[^>]*>", 
    r"<(|\/|[^\/>][^>]+|\/[^>][^>]+)>",  
    r"(alert|prompt|confirm)",  
    r"<script\b[^>]>[^>]?alert\b.*?<\/script>",  
    r"javascript:[^\"\']*" 
]


# Allowed and unwanted ports
allowed_ports = [80, 443, 5000] 
unwanted_ports = [22, 25, 139, 8080]  

# Dictionary to store request counts per IP address
request_counts = {}
# Dictionary to store packet counts per IP address for DoS detection
packet_counts = {}
# Thresholds for DoS detection
dos_threshold = 100  
dos_timeframe = 60  

def check_sql_injection(user_input):
    for field_name, field_value in user_input.items():
        for pattern in sql_injection_patterns:
            if re.search(pattern, field_value, re.IGNORECASE):
                return True
            # print(pattern)  

    return False

def check_xss(user_input):
    for field_name, field_value in user_input.items():
        for pattern in xss_patterns:
            if re.search(pattern, field_value, re.IGNORECASE):
                return True
            # print(pattern)  
    return False

@app.before_request
def before_request_func():
    ip_address = request.remote_addr
    if ip_address in request_counts:
        request_counts[ip_address] += 1
        print(f"IP: {ip_address}, Count: {request_counts[ip_address]}")  
    else:
        request_counts[ip_address] = 1

    target_url = request.headers.get('X-Forwarded-Host')  
    if not target_url:  
        target_url = request.url
    fetched_content = fetch_and_apply_waf(target_url)
    return Response(fetched_content, content_type='text/html')  

def fetch_and_apply_waf(target_url):
    response = requests.get(target_url)
    # Input Extraction (Form and Query String)
    user_input = extract_user_input_from_response(response.text)
    # Attack Detection
    if check_sql_injection(user_input):
        return "Blocked by WAF: Potential SQL detected!"
    if check_xss(user_input):
        return "Blocked by WAF: Potential XSS detected!"
    
    soup = BeautifulSoup(response.text, 'html.parser')
    for img in soup.find_all('img'):
        if 'src' in img.attrs:
            img_url = img['src']
            # Modify the image URL if necessary
            if not img_url.startswith('http'):  # Check if it's a relative URL
                img['src'] = urllib.parse.urljoin(target_url, img_url)  # Resolve relative URLs
    modified_content = str(soup)
    with open("content.txt", "a") as my_file:
        my_file.write(modified_content)
    return modified_content

def extract_user_input_from_response(content):
    soup = BeautifulSoup(content, 'html.parser')
    user_input = {}

    for field in soup.find_all('input', {'name': True}): 
        field_name = field['name']
        field_value = field.get('value', '')
        user_input[field_name] = field_value 

    for field in soup.find_all('textarea', {'name': True}):
        field_name = field['name']
        field_value = field.text or '' 
        user_input[field_name] = field_value

    query_string = request.query_string.decode()  # Get raw query string
    params = query_string.split('&')
    user_input1 = {}
    for param in params:
        try:
            key, value = param.split('=')
            user_input1[key] = value
        except ValueError:
            pass                            # Ignore malformed query parameters
    for key, value in user_input1.items():
        user_input1[key] = urllib.parse.unquote(value)
    if query_string: 
        user_input.update(user_input1)
    # print(user_input)
    return user_input

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user_data = request.form.get('user_data', '') 
        print(user_data)
        return "Data received!"  
    return "Welcome to the homepage!"

if __name__ == '__main__':
    app.run(debug=True)
    print("Server Stopped")
    