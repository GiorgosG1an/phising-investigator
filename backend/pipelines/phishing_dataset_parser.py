"""
phishing_dataset_parser.py

Author: Giannopoulos Georgios

This module provides functions to parse, decode, and extract features from raw phishing email datasets.
It processes email files, extracts headers and body content, detects URL obfuscation, calculates HTML content ratios,
and outputs structured JSONL files for downstream analysis or machine learning tasks.

Main functionalities include:
- Parsing email headers and bodies, handling malformed charsets and encodings.
- Extracting URLs and domains from HTML content.
- Detecting obfuscated URLs and calculating HTML-to-text ratios.
- Extracting authentication results (SPF, DKIM, DMARC) and spam scores.
- Identifying attachments and labeling emails as phishing.

"""
import base64
import json
import quopri
import re
import email
import codecs

from typing import List, Dict
from bs4 import BeautifulSoup
from email.parser import Parser
from email.policy import default
from urllib.parse import urlparse

def extract_urls_from_html(html_conent: str) -> List[str]:
    """
    Extracts all URLs from anchor tags in the given HTML content.

    Args:
        html_conent (str): The HTML content as a string.
        
    Returns:
        list: A list of URLs (strings) found in the 'href' attribute of anchor tags.
    """
    soup = BeautifulSoup(html_conent, 'html.parser')
    urls = []

    for tag in soup.find_all('a', href=True):
        urls.append(tag['href'])
    
    return urls

def detect_url_obfuscation(urls: List[str]) -> int:
    """
    Detects whether any URL in the provided list is obfuscated.
    Obfuscation is determined by the presence of percent-encoding (e.g., '%20') or
    an IP address in the URL.

    Args:
        urls (list of str): List of URLs to check for obfuscation.

    Returns:
        int: 1 if any URL is obfuscated, 0 otherwise.
    """
    obfuscated = 0
    for url in urls:
        if re.search(r'%[0-9A-Fa-f]{2}', url) or re.search(r'\d+\.\d+\.\d+\.\d+', url):
            obfuscated = 1
            break

    return obfuscated

def html_content_ratio(body_html: str) -> float:
    """
    Calculates the ratio of HTML content to text content in a given HTML string.
    This function parses the input HTML, extracts the text content, and computes the ratio
    of non-text (HTML markup) to the total length of the HTML. The result is rounded to two decimal places.

    Args:
        body_html (str): The HTML content as a string.

    Returns:
        float: The ratio of HTML markup to total content length. Returns 0 if the input is empty.
    """
    text_content = BeautifulSoup(body_html, 'html.parser').get_text()
    html_len = len(body_html)
    text_len = len(text_content)

    if html_len == 0:
        return 0
    else:
        return round(1 - (text_len / html_len), 2)
    
def parse_headers(raw_headers: str) -> Dict:
    """
    Parses raw email headers and extracts relevant information.

    Args:
        raw_headers (str): The raw email headers as a string.

    Returns:
        dict: A dictionary
    """
    headers = Parser(policy=default).parsestr(raw_headers)

    return {
        'from_address': headers.get('From'),
        'from_domain': headers.get('From').split('@')[-1] if headers.get('From') else '',
        'subject': headers.get('Subject'),
        'spf_result': extract_auth_result(headers.get('Authentication-Results'), 'spf'),
        'dkim_result': extract_auth_result(headers.get('Authentication-Results'), 'dkim'),
        'dmarc_result': extract_auth_result(headers.get('Authentication-Results'), 'dmarc'),
        'spam_score': extract_spam_score(headers.get('X-Spam-Status'))
    }

def extract_auth_result(header_value, key):
    """
    Extracts the authentication result for a specified key from an email header value.

    Args:
        header_value (str): The email header string to search within.
        key (str): The authentication key to look for (e.g., 'dkim', 'spf').

    Returns:
        str: The extracted authentication result if found; otherwise, 'none'.
    """
    if not header_value:
        return 'none'
    
    match = re.search(rf'{key}=([a-zA-Z]+)', header_value)
    return match.group(1) if match else 'none'

def extract_spam_score(spam_header):
    """
    Extracts the spam score from a given spam header string.

    Args:
        spam_header (str): The header string containing the spam score information.

    Returns:
        float: The extracted spam score as a float. Returns 0.0 if the score is not found or the header is empty.
    """
    if not spam_header:
        return 0.0
    
    match = re.search(r'score=(\d+\.\d+)', spam_header)
    return float(match.group(1)) if match else 0.0

def decode_email_body(body_raw: str, content_transfer_encoding:str) -> str:
    """
    Decodes an email body based on the specified content transfer encoding.

    Parameters:
        body_raw (str): The raw email body as a string.
        content_transfer_encoding (str): The encoding type of the email body. Supported values are 'base64' and 'quoted-printable'.

    Returns:
        str: The decoded email body as a string. If decoding fails or the encoding type is unsupported, returns the original body_raw.
    """
    if content_transfer_encoding == 'base64':
        try:
            decoded_bytes = base64.b64decode(body_raw.encode('utf-8', errors='ignore'), validate=False)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return body_raw  
    elif content_transfer_encoding == 'quoted-printable':
        try:
            return quopri.decodestring(body_raw.encode('utf-8', errors='ignore')).decode('utf-8', errors='ignore')
        except Exception:
            return body_raw  
    else:
        return body_raw  
    
def get_clean_charset(part, default='utf-8'):
    """
    Tries to find a valid character encoding from an email part.
    """
    charset = part.get_content_charset()
    
    if not charset:
        return default

    # Clean the charset string and test if it's a valid encoding
    try:
        # The lower() method is important as encodings are case-insensitive
        # e.g., 'UTF-8' and 'utf-8' are the same.
        cleaned_charset = charset.strip().lower()
        codecs.lookup(cleaned_charset)
        return cleaned_charset
    except LookupError:
        # The charset from the header is invalid, e.g., "utf-8x-priority: 3"
        # Try to extract the first part of it.
        potential_charset = charset.split(';')[0].split(' ')[0].strip().lower()
        try:
            codecs.lookup(potential_charset)
            return potential_charset
        except LookupError:
            # If even the cleaned version is invalid, fall back to the default
            # print(f"WARNING: Could not find a valid encoding for '{charset}'. Falling back to '{default}'.")
            return default
    
def parse_email_body(raw_email_content: str) -> dict:
    """
    Parses the raw content of an email, decodes its parts, and extracts text.
    Handles malformed charset headers.
    """
    msg = email.message_from_string(raw_email_content, policy=default)
    
    body_plain = None
    body_html = None

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition or part.is_attachment():
                continue

            if content_type == "text/plain" and body_plain is None:
                payload = part.get_payload(decode=True)
                # --- MODIFIED PART ---
                charset = get_clean_charset(part)
                try:
                    body_plain = payload.decode(charset, errors='replace')
                except (AttributeError, TypeError):
                    # Payload might not be bytes if decode=True failed
                    # in a weird way, or it's already a string.
                    body_plain = str(payload) if payload else None
            
            elif content_type == "text/html" and body_html is None:
                payload = part.get_payload(decode=True)
                # --- MODIFIED PART ---
                charset = get_clean_charset(part)
                try:
                    body_html = payload.decode(charset, errors='replace')
                except (AttributeError, TypeError):
                    body_html = str(payload) if payload else None
    else:
        # Not a multipart message
        payload = msg.get_payload(decode=True)
        # --- MODIFIED PART ---
        charset = get_clean_charset(msg)
        try:
            decoded_payload = payload.decode(charset, errors='replace')
            if msg.get_content_type() == "text/plain":
                body_plain = decoded_payload
            elif msg.get_content_type() == "text/html":
                body_html = decoded_payload
        except (AttributeError, TypeError):
            # Fallback for non-bytes payload
            decoded_payload = str(payload) if payload else None
            if msg.get_content_type() == "text/plain":
                body_plain = decoded_payload
            elif msg.get_content_type() == "text/html":
                body_html = decoded_payload

    body_text_from_html = None
    if body_html:
        try:
            soup = BeautifulSoup(body_html, 'html.parser')
            body_text_from_html = soup.get_text(separator=' ', strip=True)
        except Exception:
            # In case BeautifulSoup fails on very malformed HTML
            body_text_from_html = None

    return {
        "body_plain": body_plain,
        "body_html": body_html,
        "body_text_from_html": body_text_from_html,
    }
# --- Main Processing Function ---
def process_phishing_emails(input_file: str, output_file: str):
    """
    Processes a file containing raw phishing emails, extracts relevant features from each email, 
    and writes the parsed results to an output file in JSON lines format.
    """

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    emails = re.split(r'\nFrom [^\n]+\n', content)
    parsed_emails = []

    for raw_email in emails:
        if 'Subject:' not in raw_email:
            continue # skip metadata entries

        header_body_split = raw_email.split('\n\n', 1)
        if len(header_body_split) != 2:
            continue # invalid email structure

        headers_raw, body_raw = header_body_split
        headers = parse_headers(headers_raw)
        
        parsed_body = parse_email_body(raw_email)
        body_text = parsed_body['body_text_from_html'] or parsed_body['body_plain'] or ''

        urls = extract_urls_from_html(parsed_body['body_html'] or '')
        url_domains = list(set([urlparse(url).netloc for url in urls]))
        url_obfuscation = detect_url_obfuscation(urls)
        html_ratio_val = html_content_ratio(parsed_body['body_html'] or '')


        has_attachments = 1 if 'Content-Disposition: attachment' in raw_email else 0

        parsed_email = {
            'subject': headers['subject'],
            'from_address': headers['from_address'],
            'from_domain': headers['from_domain'],
            # 'body_text': BeautifulSoup(decoded_body, 'html.parser').get_text(separator=' ', strip=True),
            'body_text': body_text,
            'num_urls': len(urls),
            'url_domains': url_domains,
            'url_obfuscation': url_obfuscation,
            'spf_result': headers['spf_result'],
            'dkim_result': headers['dkim_result'],
            'dmarc_result': headers['dmarc_result'],
            'spam_score': headers['spam_score'],
            'has_attachments': has_attachments,
            'html_ratio': html_ratio_val,
            'label': 1  # This is phishing corpus
        }

        parsed_emails.append(parsed_email)

    with open(output_file, 'w', encoding='utf-8') as out_f:
        for email in parsed_emails:
            out_f.write(json.dumps(email) + '\n')
    
    print(f'Processed {len(parsed_emails)} phishing emails into {output_file}')

if __name__ == '__main__':
    process_phishing_emails('backend/data/raw/phishing-2022.txt', 'backend/data/processed/phishing-2022.jsonl')
    process_phishing_emails('backend/data/raw/phishing-2023.txt', 'backend/data/processed/phishing-2023.jsonl')
    process_phishing_emails('backend/data/raw/phishing-2024.txt', 'backend/data/processed/phishing-2024.jsonl')
