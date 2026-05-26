#!/usr/bin/env python3
"""
Regex Data Extraction & Secure Validation Tool

Extracts structured data from raw text using Python's `re` library,
classifies ALU-specific email addresses, and flags hostile or malformed
input before it can reach downstream systems.

Author: Jacques Twizeyimana
Date: 02nd February 2026
"""

import re
import json
import sys
import os
from typing import Dict, List, Any
from dataclasses import dataclass, field


# =============================================================================
# REGEX PATTERNS — DATA EXTRACTION
# =============================================================================

# Email: username@domain.tld
# [a-zA-Z0-9._%+-]+  local part allows dots, underscores, plus signs
# [a-zA-Z0-9.-]+     domain label characters
# \.[a-zA-Z]{2,}     TLD must be at least 2 letters
EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    re.IGNORECASE
)

# URLs: http(s) only — deliberately excludes file://, javascript:, data:
# Handles optional www, ports, paths, and query strings
URL_PATTERN = re.compile(
    r'\bhttps?://(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*'
    r'(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*'
    r'(?:\.[a-zA-Z]{2,})?(?::\d{1,5})?(?:/[^\s<>"\\]*)?',
    re.IGNORECASE
)

# Phone numbers: US formats with optional +1 country code
# Handles (555) 123-4567, 555-987-6543, +1 555.123.4567
PHONE_PATTERN = re.compile(
    r'(?:\+1[\s.-]?)?\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}\b'
)

# Credit cards: 16-digit groups of four separated by spaces or dashes
# All matches are masked in output (PCI DSS compliance)
CREDIT_CARD_PATTERN = re.compile(
    r'\b(?:\d{4}[\s-]?){3}\d{4}\b'
)

# HTML tags: opening, closing, and self-closing; attributes included
HTML_TAG_PATTERN = re.compile(
    r'</?[a-zA-Z][a-zA-Z0-9]*(?:\s+[^>]*)?\s*/?>',
    re.IGNORECASE
)

# Hashtags: # followed by a letter/underscore then alphanumerics
# Requires letter/underscore first to avoid matching bare numbers (#123)
HASHTAG_PATTERN = re.compile(
    r'#[a-zA-Z_][a-zA-Z0-9_]*\b'
)


# =============================================================================
# ALU-SPECIFIC EMAIL VALIDATION
# =============================================================================
# Three distinct address classes are validated:
#   Official staff/student : @alueducation.com
#   Alumni network         : @alumni.alueducation.com
#   Social Innovation Hub  : @si.alueducation.com
#
# Each pattern anchors the subdomain tightly so that lookalike domains such as
# @alu.education.com or @alueducation.co are rejected.
# =============================================================================

ALU_OFFICIAL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@alueducation\.com\b',
    re.IGNORECASE
)

ALU_ALUMNI_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@alumni\.alueducation\.com\b',
    re.IGNORECASE
)

ALU_SI_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@si\.alueducation\.com\b',
    re.IGNORECASE
)


# =============================================================================
# SECURITY PATTERNS — THREAT DETECTION
# =============================================================================

# SQL injection: keywords that should never appear in free-form text fields
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

# XSS: script tags, inline event handlers, dangerous URI schemes
XSS_INJECTION_PATTERNS = [
    re.compile(r'<script\b[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'\bjavascript\s*:', re.IGNORECASE),
    re.compile(r'\bon\w+\s*=', re.IGNORECASE),
    re.compile(r'\bdata\s*:', re.IGNORECASE),
    re.compile(r'<\s*iframe\b', re.IGNORECASE),
    re.compile(r'<\s*object\b', re.IGNORECASE),
    re.compile(r'<\s*embed\b', re.IGNORECASE),
    re.compile(r'<\s*form\b[^>]*\baction\s*=', re.IGNORECASE),
]

DANGEROUS_TAGS = {'script', 'iframe', 'object', 'embed', 'form', 'meta', 'link', 'style'}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ExtractionResult:
    data_type: str
    matches: List[str] = field(default_factory=list)
    masked_matches: List[str] = field(default_factory=list)
    count: int = 0
    security_warnings: List[str] = field(default_factory=list)


@dataclass
class AluEmailResult:
    official: List[str] = field(default_factory=list)
    alumni: List[str] = field(default_factory=list)
    si: List[str] = field(default_factory=list)


@dataclass
class SecurityReport:
    sql_injection_attempts: List[str] = field(default_factory=list)
    xss_attempts: List[str] = field(default_factory=list)
    dangerous_tags: List[str] = field(default_factory=list)
    is_safe: bool = True


# =============================================================================
# EXTRACTION FUNCTIONS
# =============================================================================

def extract_emails(text: str) -> ExtractionResult:
    """
    Finds all email addresses and partially masks the local part.
    Example: john.doe@example.com -> joh*****@example.com
    """
    result = ExtractionResult(data_type="emails")
    for email in EMAIL_PATTERN.findall(text):
        result.matches.append(email)
        local, domain = email.split('@', 1)
        masked = (local[:3] + '*' * (len(local) - 3) if len(local) > 3 else local) + '@' + domain
        result.masked_matches.append(masked)
    result.count = len(result.matches)
    return result


def validate_alu_emails(text: str) -> AluEmailResult:
    """
    Identifies and classifies ALU-specific email addresses.

    Three address classes are recognised:
      - official : @alueducation.com           (staff and current students)
      - alumni   : @alumni.alueducation.com    (graduates)
      - si       : @si.alueducation.com        (Social Innovation Hub)

    Lookalike domains (@alu.education.com, @alueducation.co, etc.) do not
    match any pattern and are silently excluded.
    """
    return AluEmailResult(
        official=ALU_OFFICIAL_PATTERN.findall(text),
        alumni=ALU_ALUMNI_PATTERN.findall(text),
        si=ALU_SI_PATTERN.findall(text),
    )


def extract_urls(text: str) -> ExtractionResult:
    """Finds HTTP/HTTPS URLs. Non-http schemes are not extracted."""
    result = ExtractionResult(data_type="urls")
    for url in URL_PATTERN.findall(text):
        result.matches.append(url)
        result.masked_matches.append(url)
    result.count = len(result.matches)
    return result


def extract_phone_numbers(text: str) -> ExtractionResult:
    """
    Finds US phone numbers and masks all but the last 4 digits.
    Example: (555) 123-4567 -> ******4567
    """
    result = ExtractionResult(data_type="phone_numbers")
    for phone in PHONE_PATTERN.findall(text):
        result.matches.append(phone)
        digits = re.sub(r'\D', '', phone)
        result.masked_matches.append('*' * (len(digits) - 4) + digits[-4:])
    result.count = len(result.matches)
    return result


def extract_credit_cards(text: str) -> ExtractionResult:
    """
    Finds 16-digit credit card numbers and strictly masks them.
    Only the last 4 digits are retained in the output (PCI DSS standard).
    """
    result = ExtractionResult(data_type="credit_cards")
    for card in CREDIT_CARD_PATTERN.findall(text):
        digits = re.sub(r'\D', '', card)
        if len(digits) == 16:
            result.matches.append(card)
            result.masked_matches.append('**** **** **** ' + digits[-4:])
            result.security_warnings.append(
                f"Sensitive data (credit card) detected and masked: ****{digits[-4:]}"
            )
    result.count = len(result.matches)
    return result


def extract_html_tags(text: str) -> ExtractionResult:
    """
    Extracts HTML tags and flags any that belong to the dangerous-tag set
    (script, iframe, object, embed, form, meta, link, style).
    """
    result = ExtractionResult(data_type="html_tags")
    for tag in HTML_TAG_PATTERN.findall(text):
        result.matches.append(tag)
        result.masked_matches.append(tag)
        tag_name = re.search(r'</?(\w+)', tag)
        if tag_name and tag_name.group(1).lower() in DANGEROUS_TAGS:
            result.security_warnings.append(
                f"Potentially dangerous HTML tag detected: {tag}"
            )
    result.count = len(result.matches)
    return result


def extract_hashtags(text: str) -> ExtractionResult:
    """Extracts social-media style hashtags."""
    result = ExtractionResult(data_type="hashtags")
    for tag in HASHTAG_PATTERN.findall(text):
        result.matches.append(tag)
        result.masked_matches.append(tag)
    result.count = len(result.matches)
    return result


# =============================================================================
# SECURITY FUNCTIONS
# =============================================================================

def check_security_threats(text: str) -> SecurityReport:
    """
    Scans input for SQL injection, XSS patterns, and dangerous HTML tags.
    Called before any extraction so hostile input is reported regardless of
    whether valid data is also present.
    """
    report = SecurityReport()

    for pattern in SQL_INJECTION_PATTERNS:
        for match in pattern.findall(text):
            report.sql_injection_attempts.append(match)
            report.is_safe = False

    for pattern in XSS_INJECTION_PATTERNS:
        for match in pattern.findall(text):
            report.xss_attempts.append(match if isinstance(match, str) else str(match))
            report.is_safe = False

    for tag in HTML_TAG_PATTERN.findall(text):
        tag_name = re.search(r'</?(\w+)', tag)
        if tag_name and tag_name.group(1).lower() in DANGEROUS_TAGS:
            report.dangerous_tags.append(tag)
            report.is_safe = False

    return report


def sanitize_output(text: str) -> str:
    """
    Escapes HTML special characters before printing to the console.
    Prevents a malicious string from being misinterpreted if this output is
    piped into another tool or rendered in a browser.
    """
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;'))


# =============================================================================
# MAIN EXTRACTION COORDINATOR
# =============================================================================

def extract_all_data(text: str) -> Dict[str, Any]:
    """
    Orchestrates the full extraction pipeline:
      1. Security scan (runs first — hostile input is flagged immediately)
      2. General data extraction (emails, URLs, phones, cards, HTML, hashtags)
      3. ALU-specific email classification
      4. Summary statistics
    """
    security_report = check_security_threats(text)

    results = {
        'emails':        extract_emails(text),
        'urls':          extract_urls(text),
        'phone_numbers': extract_phone_numbers(text),
        'credit_cards':  extract_credit_cards(text),
        'html_tags':     extract_html_tags(text),
        'hashtags':      extract_hashtags(text),
    }

    alu = validate_alu_emails(text)

    output: Dict[str, Any] = {
        'security_report': {
            'is_safe': security_report.is_safe,
            'sql_injection_attempts': security_report.sql_injection_attempts,
            'xss_attempts': security_report.xss_attempts,
            'dangerous_tags': security_report.dangerous_tags,
        },
        'alu_email_validation': {
            'official': {
                'domain': '@alueducation.com',
                'count': len(alu.official),
                'addresses': alu.official,
            },
            'alumni': {
                'domain': '@alumni.alueducation.com',
                'count': len(alu.alumni),
                'addresses': alu.alumni,
            },
            'si': {
                'domain': '@si.alueducation.com',
                'count': len(alu.si),
                'addresses': alu.si,
            },
            'total_alu_addresses': len(alu.official) + len(alu.alumni) + len(alu.si),
        },
        'extracted_data': {},
        'statistics': {
            'total_items_found': 0,
            'security_warnings': 0,
        },
    }

    all_warnings: List[str] = []
    for data_type, result in results.items():
        output['extracted_data'][data_type] = {
            'count': result.count,
            'items': result.masked_matches,
            'security_warnings': result.security_warnings,
        }
        output['statistics']['total_items_found'] += result.count
        all_warnings.extend(result.security_warnings)

    output['statistics']['security_warnings'] = len(all_warnings)

    if not security_report.is_safe:
        output['security_report']['warning'] = (
            "SECURITY ALERT: Potentially malicious content detected. "
            "Review the injection attempts listed above before processing further."
        )

    return output


# =============================================================================
# FILE I/O
# =============================================================================

def read_input_file(filepath: str) -> str:
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
    os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
    print(f"Results saved to: {filepath}")


# =============================================================================
# CONSOLE OUTPUT
# =============================================================================

def print_results(output: Dict[str, Any]) -> None:
    print("\n" + "=" * 60)
    print("  REGEX DATA EXTRACTION RESULTS")
    print("=" * 60)

    security = output['security_report']
    if not security['is_safe']:
        print("\n  [!] SECURITY WARNINGS:")
        print("-" * 40)
        if security['sql_injection_attempts']:
            print(f"  SQL Injection Attempts : {len(security['sql_injection_attempts'])}")
            for a in security['sql_injection_attempts'][:3]:
                print(f"    - {a!r}")
        if security['xss_attempts']:
            print(f"  XSS Attempts           : {len(security['xss_attempts'])}")
            for a in security['xss_attempts'][:3]:
                print(f"    - {sanitize_output(str(a)[:60])}")
        if security['dangerous_tags']:
            print(f"  Dangerous HTML Tags    : {len(security['dangerous_tags'])}")
            for t in security['dangerous_tags'][:3]:
                print(f"    - {sanitize_output(t)}")
    else:
        print("\n  No security threats detected.")

    # ALU email validation
    alu = output['alu_email_validation']
    print("\n  ALU EMAIL VALIDATION:")
    print("-" * 40)
    print(f"  Total ALU addresses found: {alu['total_alu_addresses']}")
    for category in ('official', 'alumni', 'si'):
        group = alu[category]
        print(f"\n  {category.upper()} ({group['domain']}): {group['count']} found")
        for addr in group['addresses']:
            print(f"    - {addr}")

    # General extractions
    print("\n  EXTRACTED DATA:")
    print("-" * 40)
    for data_type, data in output['extracted_data'].items():
        label = data_type.upper().replace('_', ' ')
        print(f"\n  {label}: {data['count']} found")
        for item in data['items'][:5]:
            print(f"    - {item}")
        if len(data['items']) > 5:
            print(f"    ... and {len(data['items']) - 5} more")

    stats = output['statistics']
    print("\n  STATISTICS:")
    print("-" * 40)
    print(f"  Total items extracted : {stats['total_items_found']}")
    print(f"  Security warnings     : {stats['security_warnings']}")
    print("\n" + "=" * 60 + "\n")


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    print("\nRegex Data Extraction & Validation Tool")
    print("Version 2.0 — May 2026\n")

    # Default paths relative to the project root (one level above src/)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    default_input = os.path.join(project_root, 'input', 'raw-text.txt')
    default_output = os.path.join(project_root, 'output', 'sample-output.json')

    input_file = sys.argv[1] if len(sys.argv) >= 2 else default_input
    output_file = sys.argv[2] if len(sys.argv) >= 3 else default_output

    print(f"Reading input from : {input_file}")
    text = read_input_file(input_file)
    print(f"Input size         : {len(text)} characters\n")

    print("Extracting data...")
    output = extract_all_data(text)

    print_results(output)
    save_output(output, output_file)


if __name__ == '__main__':
    main()
