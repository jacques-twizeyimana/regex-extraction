# Regex Data Extraction & Secure Validation Tool

A Python tool that extracts structured data from raw text using regex, validates ALU-specific email addresses, and detects hostile or malformed input before it can reach downstream systems.

## Project Structure

```
alu-regex-data-extraction_jacques-twizeyimana/
├── input/
│   └── raw-text.txt          # Sample production-style input text
├── src/
│   └── main.py               # Extraction, validation, and security logic
├── output/
│   └── sample-output.json    # Pre-generated results for verification
└── README.md
```

## Running the Tool

```bash
# Run against the included sample data (default)
python3 src/main.py

# Specify a custom input file
python3 src/main.py path/to/input.txt

# Specify both input and output paths
python3 src/main.py path/to/input.txt path/to/output.json
```

The script prints a readable report to the console and saves a detailed JSON file to `output/sample-output.json`.

## What It Extracts

Six data types are extracted using purpose-built regex patterns:

| Data Type        | Example Matches                                       |
| ---------------- | ----------------------------------------------------- |
| **Emails**       | `jane.doe@company.com`, `contact+sales@site.org`      |
| **URLs**         | `https://www.google.com`, `http://localhost:8080/api` |
| **Phone Numbers**| `(555) 123-4567`, `+1 555-0199`, `123.456.7890`       |
| **Credit Cards** | `1234 5678 9012 3456`, `1234-5678-9012-3456`          |
| **HTML Tags**    | `<div class="main">`, `<img src="logo.png" />`        |
| **Hashtags**     | `#Python`, `#coding_is_fun`                           |

## ALU-Specific Email Validation

In addition to general email extraction, the tool validates and classifies ALU email addresses into three distinct categories:

| Category | Domain | Description |
|----------|--------|-------------|
| **Official** | `@alueducation.com` | Current staff and students |
| **Alumni** | `@alumni.alueducation.com` | Graduates of ALU programmes |
| **SI** | `@si.alueducation.com` | Social Innovation Hub members |

Each pattern is anchored tightly so that lookalike or mistyped domains are rejected:

- `user@alu.education.com` — **rejected** (different domain structure)
- `user@alueducation.co` — **rejected** (wrong TLD)
- `@alueducation.com` — **rejected** (missing local part)
- `user@@alueducation.com` — **rejected** (malformed double-at)

ALU results appear in the output under `alu_email_validation` as a separate block from general emails.

## Security Features

Input from external APIs is never automatically trusted. The tool defends against three categories of hostile input:

### 1. Sensitive Data Masking

Sensitive fields are partially hidden in all output to prevent accidental exposure in logs:

- **Credit cards** — only the last 4 digits are shown: `**** **** **** 1234`
- **Email addresses** — the local part is partially hidden: `jan***@example.com`
- **Phone numbers** — all but the last 4 digits are masked: `******4567`

### 2. Injection Detection

The security scan runs **before** any extraction. If threats are found, they are reported and the overall result is flagged `"is_safe": false`.

- **SQL Injection** — detects `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `--` comments, and similar patterns
- **XSS (Cross-Site Scripting)** — detects `<script>` tags, `javascript:` URIs, and inline event handlers such as `onerror=`

### 3. Safe Console Output

Text is HTML-escaped before printing to the console. A malicious string like `<script>alert(1)</script>` is rendered as `&lt;script&gt;alert(1)&lt;/script&gt;` rather than being passed through verbatim.

## Regex Patterns Explained

### Email Address

```
\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b
```

Matches the standard `user@domain.tld` structure. Requires the TLD to be at least two letters and allows common symbols (`.`, `+`, `_`) in the local part.

### ALU Official Email

```
\b[a-zA-Z0-9._%+-]+@alueducation\.com\b
```

Anchors the domain exactly to `alueducation.com`. The escaped dot prevents `alueducationXcom` from matching.

### ALU Alumni Email

```
\b[a-zA-Z0-9._%+-]+@alumni\.alueducation\.com\b
```

Requires the full subdomain `alumni.alueducation.com`. Rejects addresses that only match the parent domain.

### ALU SI Email

```
\b[a-zA-Z0-9._%+-]+@si\.alueducation\.com\b
```

Same anchoring strategy applied to the `si` subdomain.

### URLs

```
\bhttps?://(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*...
```

Strictly allows only `http` and `https` protocols. This excludes `javascript:`, `file://`, `data:`, and other schemes that could be exploited.

### Credit Card Numbers

```
\b(?:\d{4}[\s-]?){3}\d{4}\b
```

Matches 16-digit numbers in groups of four, separated by optional spaces or dashes (the two most common manual-entry formats).

### Phone Numbers

```
(?:\+1[\s.-]?)?\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}\b
```

Handles US formats including area codes in parentheses, dot/dash/space separators, and the optional `+1` country code.

### HTML Tags

```
</?[a-zA-Z][a-zA-Z0-9]*(?:\s+[^>]*)?\s*/?>
```

Captures opening, closing, and self-closing tags along with their attributes. Tags from the dangerous set (`script`, `iframe`, `object`, `embed`, `form`, `meta`, `link`, `style`) are flagged as security warnings.

### Hashtags

```
#[a-zA-Z_][a-zA-Z0-9_]*\b
```

Requires the first character after `#` to be a letter or underscore, preventing bare numeric tokens like `#123` from being treated as hashtags.

## Author

**Jacques Twizeyimana**  
Junior Frontend Developer  
ALU Data Extraction & Secure Validation Assignment
