# Regex Data Extraction & Secure Validation Tool

A Python-based tool that extracts structured data from raw text using regex patterns while implementing security validation to handle malicious or malformed input.

## 📋 Overview

This tool was developed as part of the ALU Data Extraction & Secure Validation Assignment. It extracts **6 different data types** from raw text and implements comprehensive security measures to detect and handle potentially malicious input.

## ✨ Features

### Data Extraction (6 Types)

| Data Type           | Format Examples                                                 |
| ------------------- | --------------------------------------------------------------- |
| **Email Addresses** | `user@example.com`, `first.last@company.co.uk`                  |
| **URLs**            | `https://www.example.com`, `https://api.example.com/v2?key=val` |
| **Phone Numbers**   | `(123) 456-7890`, `123-456-7890`, `+1 555.123.4567`             |
| **Credit Cards**    | `1234 5678 9012 3456`, `1234-5678-9012-3456`                    |
| **HTML Tags**       | `<p>`, `<div class="example">`, `<img src="..." />`             |
| **Hashtags**        | `#example`, `#ThisIsAHashtag`                                   |

### Security Features

- 🔒 **Credit Card Masking**: Only last 4 digits shown in output
- 🛡️ **SQL Injection Detection**: Detects `UNION SELECT`, `OR 1=1`, `DROP TABLE`, etc.
- 🚫 **XSS Prevention**: Flags `<script>`, `javascript:`, event handlers
- ⚠️ **Dangerous HTML Detection**: Identifies `<iframe>`, `<object>`, `<embed>`, `<form>`
- 🔐 **Email Masking**: Partially masks email addresses in output

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/alu-regex.git
cd alu-regex

# No external dependencies required - uses Python standard library only
python3 --version  # Requires Python 3.6+
```

## 📖 Usage

### Basic Usage

```bash
# Run with default sample input
python3 regex_extractor.py

# Run with custom input file
python3 regex_extractor.py your_input.txt

# Specify output file
python3 regex_extractor.py your_input.txt custom_output.json
```

### Sample Output

```
🔍 Regex Data Extraction & Validation Tool
   Version 1.0 - February 2026

Reading input from: sample_input.txt
Input size: 5432 characters
Extracting data...

============================================================
  REGEX DATA EXTRACTION RESULTS
============================================================

⚠️  SECURITY WARNINGS:
----------------------------------------
  SQL Injection Attempts: 3
    • OR 1=1 --
    • DROP TABLE users
    • UNION SELECT * FROM
  XSS Attempts: 2
    • <script>alert('XSS')</script>
    • javascript:void(document.cookie)

📊 EXTRACTED DATA:
----------------------------------------

  EMAILS: 15 found
    • joh***@technova.com
    • sar***@technova.co.uk
    • hr.***@technova-solutions.org
    • ...

  CREDIT CARDS: 3 found
    • **** **** **** 9012
    • **** **** **** 9903
    • **** **** **** 0005

📈 STATISTICS:
----------------------------------------
  Total items extracted: 87
  Security warnings: 8
```

## 🔍 Regex Patterns Explained

### Email Pattern

```regex
\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b
```

- `[a-zA-Z0-9._%+-]+` - Local part (username)
- `@` - Literal @ symbol
- `[a-zA-Z0-9.-]+` - Domain name
- `\.[a-zA-Z]{2,}` - TLD (at least 2 characters)

### URL Pattern

```regex
\bhttps?://(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*...
```

- Only allows `http://` and `https://` schemes for security
- Rejects dangerous schemes like `javascript:` and `data:`

### Credit Card Pattern

```regex
\b(?:\d{4}[\s-]?){3}\d{4}\b
```

- Matches 16 digits in groups of 4
- Supports spaces or hyphens as separators
- **Security**: Always masked in output

### Phone Number Pattern

```regex
(?:\+1[\s.-]?)?\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}\b
```

- Optional country code (+1)
- Various separator formats (spaces, dots, hyphens)
- Parentheses optional for area code

## 🛡️ Security Considerations

### Why Security Matters

This tool processes raw text that could come from untrusted sources. Malicious actors might try to:

1. **Inject SQL commands** to manipulate databases
2. **Embed XSS scripts** to attack web applications
3. **Include dangerous HTML** to hijack user sessions

### Defensive Measures

1. **Input Validation**: All regex patterns are designed to reject obviously malformed data
2. **Output Sanitization**: HTML special characters are escaped in console output
3. **Data Masking**: Sensitive data (credit cards, emails, phones) is masked
4. **Threat Detection**: Known attack patterns are identified and flagged
5. **Safe Defaults**: Only safe URL schemes (http/https) are accepted

## 📁 File Structure

```
alu-regex/
├── regex_extractor.py   # Main extraction script
├── sample_input.txt     # Realistic sample input data
├── sample_output.json   # Generated output (after running)
├── README.md            # This documentation
├── assignment.txt       # Assignment requirements
└── rubric.txt           # Grading rubric
```

## 📝 Sample Input Design

The sample input (`sample_input.txt`) is designed to resemble real-world data:

- Company directory with realistic contact information
- Support ticket logs with mixed data types
- HTML newsletter template
- Social media posts with hashtags
- Order confirmation with payment details
- Security test cases (injection attempts, edge cases)

## ✅ Testing

```bash
# Run the extractor
python3 regex_extractor.py sample_input.txt

# Check the JSON output
cat sample_output.json | python3 -m json.tool

# Test with custom input
echo "Contact: test@email.com at (555) 123-4567" | python3 regex_extractor.py /dev/stdin
```

## 📄 License

This project was created for educational purposes as part of the ALU curriculum.

## 👤 Author

**Jacques Twizeyimana**  
Junior Frontend Developer  
February 2026
