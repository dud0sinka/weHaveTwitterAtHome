import math
import re
import bleach
from email_validator import validate_email, EmailNotValidError
from flask import request

def is_valid_username(username):
    if re.match(r'^[a-zA-Z0-9_]{3,16}$', username):
        return True
    return False

def is_valid_email(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False
    
def sanitize_input(input_str):
    return bleach.clean(input_str)

def calculate_entropy(password):
    pool = 0
    
    if re.search(r'[a-z]', password):
        pool += 26
    
    if re.search(r'[A-Z]', password):
        pool += 26
    
    if re.search(r'[0-9]', password):
        pool += 10
    
    if re.search(r'[^A-Za-z0-9]', password):
        pool += 32
    
    if pool == 0:
        return 0
    
    return len(password) * math.log2(pool)

def get_client_ip():
    real_ip = request.headers.get("X-Real-IP")
    forwarded_for = request.headers.get("X-Forwarded-For")

    if real_ip:
        return real_ip
    elif forwarded_for:
        return forwarded_for.split(",")[0]
    return request.remote_addr