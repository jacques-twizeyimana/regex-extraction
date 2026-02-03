#!/usr/bin/env python3
"""
Regex Data Extraction & Secure Validation Tool

I built this module to extract structured data from raw text using Python's `re` library.
I've also added a security layer to identify and flag potential threats like 
SQL injection or malicious scripts before they can be processed.

Author: Jacques Twizeyimana
Date: 02nd February 2026

Capabilities:
    1. Extracting emails, URLs, phones, credit cards, HTML tags, and hashtags.
    2. Masking sensitive data (like credit cards) to protect privacy.
    3. Detecting security threats (SQLi, XSS) in the input.
"""

import re
import json
import sys
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass, field


# =============================================================================
# REGEX PATTERNS
# =============================================================================

# -----------------------------------------------------------------------------
# EMAIL ADDRESSES
# -----------------------------------------------------------------------------
# username@domain.tld
#
# Technical Breakdown:
# - [a-zA-Z0-9._%+-]+ : The username. Allows dots, underscores, plus signs, etc.
# - @                 : The required separator.
# - [a-zA-Z0-9.-]+    : The domain name.
# - \.[a-zA-Z]{2,}    : The TLD. Must be >= 2 chars (e.g., .com, .io).
# -----------------------------------------------------------------------------
EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    re.IGNORECASE
)

# -----------------------------------------------------------------------------
# SECURE URLS
# -----------------------------------------------------------------------------
# HTTPS://www.example.com/path?query=param
#
# Technical Breakdown:
# - https?://       : Protocol.
# - (?:www\.)?      : Optional 'www.' prefix.
# - [a-zA-Z0-9.-]+  : Domain name.
# - ...             : Optional port, path, and query parameters.
# -----------------------------------------------------------------------------
URL_PATTERN = re.compile(
    r'\bhttps?://(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*'
    r'(?:\.[a-zA-Z]{2,})?(?::\d{1,5})?(?:/[^\s<>"\\]*)?',
    re.IGNORECASE
)

# -----------------------------------------------------------------------------
# PHONE NUMBERS
# -----------------------------------------------------------------------------
# My pattern handles the most common phone formats,
# including variations with dots, dashes, spaces, and optional country codes.
#
# Matches: (123) 456-7890, 123-456-7890, +1 555.123.4567
# -----------------------------------------------------------------------------
PHONE_PATTERN = re.compile(
    r'(?:\+1[\s.-]?)?\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}\b'
)

# -----------------------------------------------------------------------------
# CREDIT CARDS
# -----------------------------------------------------------------------------
# Identifies 16-digit card numbers grouped in fours separated by spaces or dashes.
#
# NOTE: All matches are automatically masked in the output for security (PCI DSS).
# -----------------------------------------------------------------------------
CREDIT_CARD_PATTERN = re.compile(
    r'\b(?:\d{4}[\s-]?){3}\d{4}\b'
)

# -----------------------------------------------------------------------------
# HTML TAGS
# -----------------------------------------------------------------------------
# Captures HTML tags for analysis.
# I use this to find structure (<p>, <div>) but also to spot dangerous elements
# like <script> or <object> that might indicate an injection attack.
# -----------------------------------------------------------------------------
HTML_TAG_PATTERN = re.compile(
    r'</?[a-zA-Z][a-zA-Z0-9]*(?:\s+[^>]*)?\s*/?>',
    re.IGNORECASE
)

# -----------------------------------------------------------------------------
# HASHTAGS
# -----------------------------------------------------------------------------
# Matches social-media style hashtags.
# Rule: Must start with # and be followed by a letter or underscore.
# -----------------------------------------------------------------------------
HASHTAG_PATTERN = re.compile(
    r'#[a-zA-Z_][a-zA-Z0-9_]*\b'
)


# =============================================================================
# SECURITY PATTERNS
# =============================================================================

# -----------------------------------------------------------------------------
# SQL INJECTION DETECTION
# -----------------------------------------------------------------------------
# These patterns look for common SQL commands that shouldn't be in standard text.
# If I see "UNION SELECT" or "OR 1=1" in a bio or comment field, it's a huge
# red flag for an attempted database attack.
# -----------------------------------------------------------------------------
SQL_INJECTION_PATTERNS = [
    re.compile(r'\bUNION\s+SELECT\b', re.IGNORECASE),
    re.compile(r'\bOR\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1', re.IGNORECASE),
    re.compile(r'\bAND\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1', re.IGNORECASE),
    re.compile(r'--\s*$', re.MULTILINE),
    re.compile(r'/\*.*?\*/', re.DOTALL),
    re.compile(r'\bDROP\s+TABLE\b', re.IGNORECASE),
    re.compile(r'\bDELETE\s+FROM\b', re.IGNORECASE),
    re.compile(r'\bINSERT\s+INTO\b', re.IGNORECASE),
    re.compile(r'\bEXEC\s*\(', re.IGNORECASE),
    re.compile(r';\s*--', re.IGNORECASE),
]

# -----------------------------------------------------------------------------
# XSS (SCRIPT INJECTION) DETECTION
# -----------------------------------------------------------------------------
# I'm looking for <script> tags, inline event handlers (like onclick), or
# dangerous URL schemes (javascript:) that could execute code in a browser.
# -----------------------------------------------------------------------------
XSS_INJECTION_PATTERNS = [
    re.compile(r'<script\b[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'\bjavascript\s*:', re.IGNORECASE),
    re.compile(r'\bon\w+\s*=', re.IGNORECASE),  # Matches onclick, onerror, etc.
    re.compile(r'\bdata\s*:', re.IGNORECASE),
    re.compile(r'<\s*iframe\b', re.IGNORECASE),
    re.compile(r'<\s*object\b', re.IGNORECASE),
    re.compile(r'<\s*embed\b', re.IGNORECASE),
    re.compile(r'<\s*form\b[^>]*\baction\s*=', re.IGNORECASE),
]

# A set of HTML tags that are often used maliciously.
DANGEROUS_TAGS = {'script', 'iframe', 'object', 'embed', 'form', 'meta', 'link', 'style'}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ExtractionResult:
    """Holds the results for a specific data type, including masked safe versions."""
    data_type: str
    matches: List[str] = field(default_factory=list)
    masked_matches: List[str] = field(default_factory=list)
    count: int = 0
    security_warnings: List[str] = field(default_factory=list)


@dataclass
class SecurityReport:
    """Summary of all security threats found in the input."""
    sql_injection_attempts: List[str] = field(default_factory=list)
    xss_attempts: List[str] = field(default_factory=list)
    dangerous_tags: List[str] = field(default_factory=list)
    is_safe: bool = True


# =============================================================================
# EXTRACTION FUNCTIONS
# =============================================================================

def extract_emails(text: str) -> ExtractionResult:
    """
    Finds email addresses and masks them for privacy.
    Example: 'john.doe@example.com' becomes 'joh***@example.com'
    """
    result = ExtractionResult(data_type="emails")
    matches = EMAIL_PATTERN.findall(text)
    
    for email in matches:
        result.matches.append(email)
        # Masking logic: Show first 3 chars, mask the rest of the local part.
        local, domain = email.split('@')
        if len(local) > 3:
            masked = local[:3] + '*' * (len(local) - 3) + '@' + domain
        else:
            masked = email
        result.masked_matches.append(masked)
    
    result.count = len(result.matches)
    return result


def extract_urls(text: str) -> ExtractionResult:
    """
    Finds HTTP/HTTPS URLs.
    Note: I don't mask URLs because they typically aren't sensitive in this context,
    but we do validate the protocol for security.
    """
    result = ExtractionResult(data_type="urls")
    matches = URL_PATTERN.findall(text)
    
    for url in matches:
        result.matches.append(url)
        result.masked_matches.append(url)
    
    result.count = len(result.matches)
    return result


def extract_phone_numbers(text: str) -> ExtractionResult:
    """
    Finds phone numbers and masks them to show only the last 4 digits.
    Example: '(555) 123-4567' becomes '******4567'
    """
    result = ExtractionResult(data_type="phone_numbers")
    matches = PHONE_PATTERN.findall(text)
    
    for phone in matches:
        result.matches.append(phone)
        # Strip non-digits and mask everything but the last 4.
        digits = re.sub(r'\D', '', phone)
        masked = '*' * (len(digits) - 4) + digits[-4:]
        result.masked_matches.append(masked)
    
    result.count = len(result.matches)
    return result


def extract_credit_cards(text: str) -> ExtractionResult:
    """
    Finds credit card numbers and strictly masks them.
    We only ever show the last 4 digits to comply with security standards.
    """
    result = ExtractionResult(data_type="credit_cards")
    matches = CREDIT_CARD_PATTERN.findall(text)
    
    for card in matches:
        digits = re.sub(r'\D', '', card)
        if len(digits) == 16:
            result.matches.append(card)
            # Security: Mask all but the last 4 digits.
            masked = '**** **** **** ' + digits[-4:]
            result.masked_matches.append(masked)
            result.security_warnings.append(
                f"Sensitive data (credit card) detected and masked: ****{digits[-4:]}"
            )
    
    result.count = len(result.matches)
    return result


def extract_html_tags(text: str) -> ExtractionResult:
    """
    Extracts HTML tags. If a tag is in our 'Dangerous' list (like <script>),
    it gets flagged as a security warning.
    """
    result = ExtractionResult(data_type="html_tags")
    matches = HTML_TAG_PATTERN.findall(text)
    
    for tag in matches:
        result.matches.append(tag)
        result.masked_matches.append(tag)
        
        # Check if the tag is potentially harmful
        tag_name = re.search(r'</?(\w+)', tag)
        if tag_name and tag_name.group(1).lower() in DANGEROUS_TAGS:
            result.security_warnings.append(
                f"Potentially dangerous HTML tag detected: {tag}"
            )
    
    result.count = len(result.matches)
    return result


def extract_hashtags(text: str) -> ExtractionResult:
    """
    Extracts hashtags from the text.
    """
    result = ExtractionResult(data_type="hashtags")
    matches = HASHTAG_PATTERN.findall(text)
    
    for hashtag in matches:
        result.matches.append(hashtag)
        result.masked_matches.append(hashtag)
    
    result.count = len(result.matches)
    return result


# =============================================================================
# SECURITY FUNCTIONS
# =============================================================================

def check_security_threats(text: str) -> SecurityReport:
    """
    Scans the entire input text for security threats. 
    
    I look for:
    1. SQL Injection patterns
    2. XSS (Cross-Site Scripting) patterns
    3. Dangerous HTML tags
    """
    report = SecurityReport()
    
    # Check for SQL injection patterns
    for pattern in SQL_INJECTION_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            report.sql_injection_attempts.append(match)
            report.is_safe = False
    
    # Check for XSS patterns
    for pattern in XSS_INJECTION_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            match_str = match if isinstance(match, str) else str(match)
            report.xss_attempts.append(match_str)
            report.is_safe = False
    
    # Check for dangerous HTML tags
    html_tags = HTML_TAG_PATTERN.findall(text)
    for tag in html_tags:
        tag_name = re.search(r'</?(\w+)', tag)
        if tag_name and tag_name.group(1).lower() in DANGEROUS_TAGS:
            report.dangerous_tags.append(tag)
            report.is_safe = False
    
    return report


def sanitize_output(text: str) -> str:
    """
    Makes text safe for printing to the console by escaping HTML characters.
    This prevents a malicious string from messing up the terminal or
    being misinterpreted if this output is used elsewhere.
    """
    sanitized = text.replace('&', '&amp;')
    sanitized = sanitized.replace('<', '&lt;')
    sanitized = sanitized.replace('>', '&gt;')
    sanitized = sanitized.replace('"', '&quot;')
    sanitized = sanitized.replace("'", '&#x27;')
    return sanitized


# =============================================================================
# MAIN EXTRACTION FUNCTION
# =============================================================================

def extract_all_data(text: str) -> Dict[str, Any]:
    """
    The main coordinator function. 
    
    It runs the security check first, then performs all data extractions,
    and finally compiles the statistics and warnings into a single report.
    """
    # First, perform security analysis
    security_report = check_security_threats(text)
    
    # Extract all data types
    results = {
        'emails': extract_emails(text),
        'urls': extract_urls(text),
        'phone_numbers': extract_phone_numbers(text),
        'credit_cards': extract_credit_cards(text),
        'html_tags': extract_html_tags(text),
        'hashtags': extract_hashtags(text),
    }
    
    # Compile output
    output = {
        'security_report': {
            'is_safe': security_report.is_safe,
            'sql_injection_attempts': security_report.sql_injection_attempts,
            'xss_attempts': security_report.xss_attempts,
            'dangerous_tags': security_report.dangerous_tags,
        },
        'extracted_data': {},
        'statistics': {
            'total_items_found': 0,
            'security_warnings': 0,
        }
    }
    
    # Process each extraction result
    all_warnings = []
    for data_type, result in results.items():
        output['extracted_data'][data_type] = {
            'count': result.count,
            'items': result.masked_matches,  # Use masked versions in output
            'security_warnings': result.security_warnings,
        }
        output['statistics']['total_items_found'] += result.count
        all_warnings.extend(result.security_warnings)
    
    output['statistics']['security_warnings'] = len(all_warnings)
    
    # Add overall security warning if input is not safe
    if not security_report.is_safe:
        output['security_report']['warning'] = (
            "SECURITY ALERT: Potentially malicious content detected in input. "
            "Review the injection attempts above."
        )
    
    return output


# =============================================================================
# FILE I/O AND CLI
# =============================================================================

def read_input_file(filepath: str) -> str:
    """Reads the input text file, handling common errors like missing files."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied reading: {filepath}")
        sys.exit(1)


def save_output(output: Dict[str, Any], filepath: str) -> None:
    """Saves the structured JSON results to a file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
    print(f"Results saved to: {filepath}")


def print_results(output: Dict[str, Any]) -> None:
    """Prints a clean, human-readable summary of the results to the console."""
    print("\n" + "=" * 60)
    print("  REGEX DATA EXTRACTION RESULTS")
    print("=" * 60)
    
    # Security Report
    security = output['security_report']
    if not security['is_safe']:
        print("\n  SECURITY WARNINGS:")
        print("-" * 40)
        if security['sql_injection_attempts']:
            print(f"  SQL Injection Attempts: {len(security['sql_injection_attempts'])}")
            for attempt in security['sql_injection_attempts'][:3]:
                print(f"    - {attempt}")
        if security['xss_attempts']:
            print(f"  XSS Attempts: {len(security['xss_attempts'])}")
            for attempt in security['xss_attempts'][:3]:
                print(f"    - {sanitize_output(str(attempt)[:50])}")
        if security['dangerous_tags']:
            print(f"  Dangerous Tags: {len(security['dangerous_tags'])}")
            for tag in security['dangerous_tags'][:3]:
                print(f"    - {sanitize_output(tag)}")
    else:
        print("\n  No security threats detected")
    
    # Extracted Data
    print("\n  EXTRACTED DATA:")
    print("-" * 40)
    
    for data_type, data in output['extracted_data'].items():
        print(f"\n  {data_type.upper().replace('_', ' ')}: {data['count']} found")
        if data['items']:
            for item in data['items'][:5]:  # Show first 5 items
                print(f"    - {item}")
            if len(data['items']) > 5:
                print(f"    ... and {len(data['items']) - 5} more")
    
    # Statistics
    print("\n  STATISTICS:")
    print("-" * 40)
    stats = output['statistics']
    print(f"  Total items extracted: {stats['total_items_found']}")
    print(f"  Security warnings: {stats['security_warnings']}")
    
    print("\n" + "=" * 60 + "\n")


def main():
    """
    Main entry point. Handles arguments and orchestrates the flow.
    """
    print("\nRegex Data Extraction & Validation Tool")
    print("Version 1.0 - February 2026\n")
    
    # Determine input source
    if len(sys.argv) < 2:
        input_file = 'sample_input.txt'
        print(f"No input file specified. Using default: {input_file}")
    else:
        input_file = sys.argv[1]
    
    # Read input
    print(f"Reading input from: {input_file}")
    text = read_input_file(input_file)
    print(f"Input size: {len(text)} characters")
    
    # Extract data
    print("Extracting data...")
    output = extract_all_data(text)
    
    # Print results
    print_results(output)
    
    # Save output
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'sample_output.json'
    save_output(output, output_file)


if __name__ == '__main__':
    main()