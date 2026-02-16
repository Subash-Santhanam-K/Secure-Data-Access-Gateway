import base64

def encode_base64(data: str):
    """Encodes a string to Base64"""
    return base64.b64encode(data.encode()).decode()

def decode_base64(encoded_data: str):
    """Decodes a Base64 string"""
    return base64.b64decode(encoded_data.encode()).decode()
