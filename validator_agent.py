"""
Validator Agent Module (Sub-agent #2)
======================================
Cross-validates potential vulnerabilities found by the Detector Agent
against CWE (Common Weakness Enumeration) knowledge base.

Goal: HIGH PRECISION — reduce False Positives by critically evaluating
whether the flagged code is actually vulnerable or has proper sanitization.

Each vulnerability gets:
  - confidence_score (0-100)
  - status: Confirmed | False Positive | Needs Human Review
"""

import json
import logging
import time
import concurrent.futures
from typing import List, Dict
import requests
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_WORKERS = 5
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

# HITL confidence thresholds
CONFIRMED_THRESHOLD = 70       # score >= 70 → Confirmed
NEEDS_REVIEW_THRESHOLD = 40    # 40 <= score < 70 → Needs Human Review
                               # score < 40 → False Positive

# Max vulnerabilities per validation batch (to fit context window)
BATCH_SIZE = 10

# ---------------------------------------------------------------------------
# CWE Knowledge Base
# ---------------------------------------------------------------------------

CWE_DATABASE = {
    "CWE-78": {
        "name": "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
        "description": (
            "The product constructs all or part of an OS command using externally-influenced input, "
            "but does not neutralize or incorrectly neutralizes special elements that could modify "
            "the intended command. Attackers can execute arbitrary OS commands on the host."
        ),
        "mitigations": [
            "Use library calls rather than external processes to recreate the desired functionality",
            "Use parameterized/structured mechanisms that automatically enforce separation between data and command",
            "Use subprocess with shell=False and pass arguments as a list",
            "Validate and sanitize all input — use allowlists for permitted characters",
        ],
        "false_positive_indicators": [
            "Input is hardcoded or comes from a trusted internal source, not user input",
            "subprocess is used with shell=False and arguments passed as a list",
            "shlex.quote() or equivalent escaping is applied before passing to shell",
            "Input is validated against a strict allowlist of known-safe values",
        ],
    },
    "CWE-79": {
        "name": "Improper Neutralization of Input During Web Page Generation (XSS)",
        "description": (
            "The product does not neutralize or incorrectly neutralizes user-controllable input before "
            "it is placed in output used as a web page served to other users. This allows attackers to "
            "inject client-side scripts into web pages viewed by other users."
        ),
        "mitigations": [
            "Use context-aware output encoding/escaping (HTML entity encoding, JavaScript escaping, URL encoding)",
            "Use template engines with auto-escaping enabled (Jinja2 autoescape, React JSX)",
            "Implement Content Security Policy (CSP) headers",
            "Validate input on the server side — use allowlists for expected formats",
        ],
        "false_positive_indicators": [
            "Template engine with auto-escaping is used (Jinja2 with autoescape=True, React JSX, Angular templates)",
            "Output is properly escaped using framework-provided escaping functions (markupsafe.escape, html.escape)",
            "Content Security Policy headers are set and prevent inline script execution",
            "The output context is not HTML/JavaScript (e.g., server-side logging, API JSON responses)",
            "Data comes from a trusted source, not user input",
        ],
    },
    "CWE-89": {
        "name": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
        "description": (
            "The product constructs all or part of an SQL command using externally-influenced input, "
            "but does not neutralize or incorrectly neutralizes special elements that could modify "
            "the intended SQL command. Attackers can read, modify, or delete database data."
        ),
        "mitigations": [
            "Use parameterized queries (prepared statements) with bound parameters",
            "Use an ORM (SQLAlchemy, Django ORM, Hibernate) that handles parameterization automatically",
            "Apply input validation with strict type checking and allowlists",
            "Use stored procedures with parameterized inputs",
        ],
        "false_positive_indicators": [
            "ORM methods are used (e.g., SQLAlchemy session.query(), Django .filter(), Hibernate Criteria)",
            "Parameterized queries with placeholders (?, %s, :param) are used instead of string concatenation",
            "The concatenated value is not user-controllable (e.g., hardcoded table name, internal constant)",
            "Input is validated/cast to a specific type (int, UUID) before inclusion in query",
        ],
    },
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
        "description": (
            "The product uses external input to construct a pathname to a file or directory, "
            "but does not properly neutralize sequences like '../' that can resolve to a location "
            "outside the intended restricted directory."
        ),
        "mitigations": [
            "Use os.path.realpath() to resolve the canonical path and verify it stays within the allowed directory",
            "Use os.path.basename() to strip directory components from user input",
            "Validate input against an allowlist of permitted filenames or patterns",
            "Use chroot jails or containerization to limit filesystem access",
        ],
        "false_positive_indicators": [
            "Path is validated with os.path.realpath() + startswith() check against allowed base directory",
            "Only os.path.basename() of user input is used (directory components stripped)",
            "Input is validated against a strict allowlist of known filenames",
            "The path does not include any user-controllable components",
            "send_from_directory() or similar safe framework function is used",
        ],
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "description": (
            "The product exposes sensitive information to an actor not explicitly authorized to have "
            "access. This can include credentials, tokens, PII, or internal system details."
        ),
        "mitigations": [
            "Store secrets in environment variables or dedicated secret management systems",
            "Use .env files excluded from version control via .gitignore",
            "Avoid logging sensitive data — mask or redact credentials in log output",
            "Implement proper access controls for sensitive endpoints",
        ],
        "false_positive_indicators": [
            "The 'secret' is actually loaded from an environment variable (os.getenv, os.environ)",
            "The value is a placeholder, example, or template (e.g., 'your_api_key_here', 'changeme')",
            "The file is a .env.example or documentation file, not actual configuration",
            "Sensitive data is properly masked/redacted before logging",
        ],
    },
    "CWE-284": {
        "name": "Improper Access Control",
        "description": (
            "The product does not restrict or incorrectly restricts access to a resource from an "
            "unauthorized actor. This includes missing authentication checks, IDOR, and privilege escalation."
        ),
        "mitigations": [
            "Implement authentication checks on all protected endpoints",
            "Use role-based access control (RBAC) to verify authorization",
            "Validate that the authenticated user owns the requested resource (prevent IDOR)",
            "Apply the principle of least privilege",
        ],
        "false_positive_indicators": [
            "Authentication decorator or middleware is applied (@login_required, @auth.requires_auth)",
            "The endpoint is intentionally public (login page, public API, health check)",
            "Access control is implemented in a middleware/decorator not visible in the current code chunk",
            "Resource ownership is validated before access",
        ],
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "description": (
            "The product does not prove or insufficiently proves that a claimed identity is correct. "
            "This includes weak password storage, missing brute-force protection, and session fixation."
        ),
        "mitigations": [
            "Use strong password hashing (bcrypt, argon2, scrypt) with proper work factors",
            "Implement account lockout or rate limiting against brute-force attacks",
            "Use multi-factor authentication for sensitive operations",
            "Regenerate session IDs after authentication to prevent session fixation",
        ],
        "false_positive_indicators": [
            "bcrypt, argon2, or scrypt is used for password hashing",
            "Rate limiting or account lockout is implemented",
            "The code is a test/demo and not production authentication",
            "JWT or OAuth2 with proper validation is used",
        ],
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": (
            "The product deserializes untrusted data without sufficiently verifying that the "
            "resulting data will be valid. Attackers can exploit this to execute arbitrary code, "
            "perform denial-of-service, or bypass authentication."
        ),
        "mitigations": [
            "Avoid deserializing data from untrusted sources entirely",
            "Use safe alternatives: json.loads instead of pickle, yaml.safe_load instead of yaml.load",
            "Implement integrity checking (HMAC, digital signatures) on serialized data",
            "Use allowlists for permitted classes during deserialization",
        ],
        "false_positive_indicators": [
            "yaml.safe_load() or yaml.SafeLoader is used instead of yaml.load()",
            "json.loads() is used (JSON is safe for deserialization)",
            "The serialized data comes from a trusted internal source, not user input",
            "pickle is used only for internal caching with no external input path",
        ],
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": (
            "The product makes an HTTP request to a URL that is controlled by a user, "
            "allowing the attacker to make requests to internal services, read local files, "
            "or scan internal networks."
        ),
        "mitigations": [
            "Validate and sanitize all user-supplied URLs against an allowlist of permitted domains",
            "Block requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, ::1)",
            "Use a URL parser to extract and validate the hostname before making the request",
            "Disable HTTP redirects or validate redirect targets",
        ],
        "false_positive_indicators": [
            "The URL is hardcoded or comes from a trusted configuration, not user input",
            "URL validation with domain allowlist is applied before making the request",
            "Private IP ranges are explicitly blocked",
            "The request is made to a known internal API with a fixed base URL",
        ],
    },
    "CWE-16": {
        "name": "Configuration",
        "description": (
            "Weaknesses in this category are related to security misconfigurations of software. "
            "This includes debug mode enabled in production, overly permissive CORS policies, "
            "missing security headers, and default credentials."
        ),
        "mitigations": [
            "Disable debug mode in production (DEBUG=False, app.run(debug=False))",
            "Configure restrictive CORS policies — avoid Access-Control-Allow-Origin: *",
            "Set security headers: X-Frame-Options, CSP, X-Content-Type-Options, HSTS",
            "Change all default credentials and secrets before deployment",
        ],
        "false_positive_indicators": [
            "Debug mode is conditional on environment (if os.getenv('ENV') == 'development')",
            "The code is a development/test configuration, not production",
            "CORS is restricted to specific allowed origins, not wildcard",
            "Security headers are set elsewhere (reverse proxy, middleware)",
        ],
    },
}

# Fallback for unknown CWE IDs
DEFAULT_CWE_CONTEXT = {
    "name": "Unknown Weakness",
    "description": "No specific CWE entry available. Evaluate based on general security principles.",
    "mitigations": ["Apply defense-in-depth principles", "Validate all input", "Follow least privilege"],
    "false_positive_indicators": ["Input comes from a trusted source", "Proper sanitization is applied"],
}


# ---------------------------------------------------------------------------
# Validator System Prompt
# ---------------------------------------------------------------------------

VALIDATOR_SYSTEM_PROMPT = """You are a Senior Application Security Analyst performing VALIDATION of potential vulnerabilities.

Your role is the VALIDATOR — you critically evaluate findings from a Detector agent to determine if they are
TRUE vulnerabilities or FALSE POSITIVES. You must be SKEPTICAL and PRECISE.

For each potential vulnerability, you will receive:
- The vulnerability details (type, line, code snippet, description)
- CWE reference information (description, mitigations, known false positive indicators)

YOUR TASK for each vulnerability:
1. Critically evaluate: Is the flagged code ACTUALLY vulnerable, or does it have proper sanitization/escaping/protection?
2. Check against the provided FALSE POSITIVE INDICATORS — if any match, lower confidence significantly.
3. Consider the CONTEXT — is this a test file, example code, or production code?
4. Assign a confidence_score from 0 to 100:
   - 0-39:  Almost certainly a False Positive (proper protections are in place)
   - 40-69: Uncertain — requires human expert review (some protections may exist but are unclear)
   - 70-100: High confidence this is a real vulnerability (no visible protections)
5. Assign a status:
   - "Confirmed" — confidence >= 70, this is very likely a real vulnerability
   - "Needs Human Review" — confidence 40-69, an analyst should verify manually
   - "False Positive" — confidence < 40, this is not a real vulnerability

RESPONSE FORMAT:
Return a JSON array with one object per vulnerability. Each object MUST have ALL these fields:
{
  "original_index": <int>,          // The index of the vulnerability in the input array (0-based)
  "confidence_score": <int>,        // 0-100
  "status": <string>,               // "Confirmed", "False Positive", or "Needs Human Review"
  "validation_reasoning": <string>, // 2-3 sentences explaining your reasoning
  "adjusted_severity": <string>,    // Re-evaluated severity: "Critical", "High", "Medium", "Low", "Info"
  "recommendation": <string>        // Specific remediation advice if Confirmed, or why it's FP
}

IMPORTANT RULES:
- Return ONLY the JSON array, no markdown, no code fences, no extra text.
- You MUST return exactly one result per input vulnerability.
- Be CRITICAL — look for sanitization, parameterization, encoding, access control that the Detector may have missed.
- Consider the programming language's built-in protections (e.g., Jinja2 auto-escaping, Go's sql.Query with placeholders).
- If code context is insufficient to determine, lean toward "Needs Human Review" rather than "Confirmed".
"""


# ---------------------------------------------------------------------------
# Core validation functions
# ---------------------------------------------------------------------------

def _get_cwe_context(cwe_id: str) -> dict:
    """Look up CWE context from the knowledge base."""
    if not cwe_id or cwe_id == 'N/A':
        return DEFAULT_CWE_CONTEXT

    # Normalize: "CWE-89" → "CWE-89", "89" → "CWE-89"
    normalized = cwe_id.strip().upper()
    if not normalized.startswith('CWE-'):
        normalized = f'CWE-{normalized}'

    return CWE_DATABASE.get(normalized, DEFAULT_CWE_CONTEXT)


def _build_validator_prompt(vulnerabilities_batch: List[dict]) -> str:
    """
    Build the user prompt for a batch of vulnerabilities to validate.

    Each vulnerability is enriched with CWE context from the knowledge base.
    """
    entries = []

    for idx, vuln in enumerate(vulnerabilities_batch):
        cwe_id = vuln.get('cwe_id', 'N/A')
        cwe_context = _get_cwe_context(cwe_id)

        entry = f"""--- VULNERABILITY #{idx} ---
File: {vuln.get('filepath', 'unknown')}
Line: {vuln.get('line_number', '?')}
Type: {vuln.get('vulnerability_type', 'Unknown')}
Severity (from Detector): {vuln.get('severity', 'Medium')}
CWE: {cwe_id}
Code Snippet:
```
{vuln.get('code_snippet', 'N/A')}
```
Detector's Description: {vuln.get('description', 'N/A')}

CWE REFERENCE — {cwe_context['name']}:
Description: {cwe_context['description']}
Known Mitigations: {'; '.join(cwe_context['mitigations'])}
False Positive Indicators: {'; '.join(cwe_context['false_positive_indicators'])}
"""
        entries.append(entry)

    combined = '\n'.join(entries)

    return f"""Validate the following {len(vulnerabilities_batch)} potential vulnerabilities.
For each one, determine if it is a real vulnerability, a false positive, or needs human review.

{combined}

Return a JSON array with exactly {len(vulnerabilities_batch)} validation results (one per vulnerability, in order).
"""


def validate_batch(vulnerabilities: List[dict], model=None) -> List[dict]:
    """
    Validate a batch of vulnerabilities through DeepSeek API.

    Args:
        vulnerabilities: List of vulnerability dicts from the Detector.
        model: Ignored. Maintained for compatibility.

    Returns:
        List of validation result dicts.
    """
    if not vulnerabilities:
        return []

    user_prompt = _build_validator_prompt(vulnerabilities)
    last_error = None

    for attempt in range(MAX_RETRIES):
        try:
            headers = {
                "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                "Content-Type": "application/json"
            }

            payload = {
                "model": DEEPSEEK_MODEL,
                "messages": [
                    {"role": "system", "content": VALIDATOR_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.1
            }

            response = requests.post(DEEPSEEK_URL, headers=headers, json=payload, timeout=120)
            response.raise_for_status()

            raw_text = response.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            validations = _parse_validator_response(raw_text, len(vulnerabilities))
            return validations

        except Exception as e:
            last_error = str(e)
            logger.warning(
                f"Validator attempt {attempt + 1}/{MAX_RETRIES} failed: {e}"
            )
            if attempt < MAX_RETRIES - 1:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                time.sleep(delay)

    logger.error(f"All {MAX_RETRIES} validator attempts failed: {last_error}")

    # Return default "Needs Human Review" for all if API fails completely
    return [
        {
            'original_index': i,
            'confidence_score': 50,
            'status': 'Needs Human Review',
            'validation_reasoning': f'Validation failed due to API error: {last_error}',
            'adjusted_severity': vuln.get('severity', 'Medium'),
            'recommendation': 'Manual review required — automated validation was unavailable.',
        }
        for i, vuln in enumerate(vulnerabilities)
    ]


def _parse_validator_response(raw_text: str, expected_count: int) -> list:
    """
    Parse the Validator LLM response into validation results.

    Handles LLM quirks similar to detector_agent._parse_detector_response.
    """
    text = raw_text

    # Strip markdown fences
    if '```json' in text:
        text = text.split('```json', 1)[1]
        text = text.split('```', 1)[0]
    elif '```' in text:
        text = text.split('```', 1)[1]
        text = text.split('```', 1)[0]

    text = text.strip()

    # Find JSON array
    if not text.startswith('['):
        bracket_pos = text.find('[')
        if bracket_pos != -1:
            text = text[bracket_pos:]
        else:
            logger.error("Validator returned no JSON array")
            return _default_validations(expected_count)

    if not text.endswith(']'):
        last_bracket = text.rfind(']')
        if last_bracket != -1:
            text = text[:last_bracket + 1]

    # Fix common LLM JSON mistakes
    text = text.replace(',]', ']').replace(',\n]', '\n]')

    try:
        result = json.loads(text)
        if isinstance(result, list):
            validated = []
            for item in result:
                if isinstance(item, dict):
                    validated.append(_normalize_validation(item))
            # Ensure we have results for all vulnerabilities
            while len(validated) < expected_count:
                validated.append(_default_validation(len(validated)))
            return validated[:expected_count]
        else:
            logger.warning(f"Validator returned non-array JSON: {type(result)}")
            return _default_validations(expected_count)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse validator response: {e}")
        logger.debug(f"Raw text: {text[:500]}")
        return _default_validations(expected_count)


def _normalize_validation(val: dict) -> dict:
    """Ensure all required validation fields exist with correct types."""
    score = int(val.get('confidence_score', 50))
    score = max(0, min(100, score))  # clamp 0-100

    # Derive status from score if not provided or inconsistent
    status = str(val.get('status', ''))
    if status not in ('Confirmed', 'False Positive', 'Needs Human Review'):
        status = _score_to_status(score)

    return {
        'original_index': int(val.get('original_index', 0)),
        'confidence_score': score,
        'status': status,
        'validation_reasoning': str(val.get('validation_reasoning', '')),
        'adjusted_severity': str(val.get('adjusted_severity', 'Medium')),
        'recommendation': str(val.get('recommendation', '')),
    }


def _score_to_status(score: int) -> str:
    """Convert confidence score to HITL status."""
    if score >= CONFIRMED_THRESHOLD:
        return 'Confirmed'
    elif score >= NEEDS_REVIEW_THRESHOLD:
        return 'Needs Human Review'
    else:
        return 'False Positive'


def _default_validation(index: int) -> dict:
    """Create a default validation result when parsing fails."""
    return {
        'original_index': index,
        'confidence_score': 50,
        'status': 'Needs Human Review',
        'validation_reasoning': 'Automated validation could not be completed.',
        'adjusted_severity': 'Medium',
        'recommendation': 'Manual review required.',
    }


def _default_validations(count: int) -> list:
    """Create default validation results for all vulnerabilities."""
    return [_default_validation(i) for i in range(count)]


# ---------------------------------------------------------------------------
# Parallel batch processing orchestrator
# ---------------------------------------------------------------------------

def run_validator(vulnerabilities: List[dict],
                  max_workers: int = MAX_WORKERS) -> dict:
    """
    Process all vulnerabilities through the Validator Agent.

    Splits vulnerabilities into batches (BATCH_SIZE) and processes
    batches in parallel via ThreadPoolExecutor.

    Args:
        vulnerabilities: List of vulnerability dicts from the Detector Agent.
        max_workers: Max parallel API calls.

    Returns:
        Dict with:
          - validated_vulnerabilities: list of merged vulnerability + validation data
          - summary: aggregate validation statistics
    """
    if not vulnerabilities:
        return {
            'validated_vulnerabilities': [],
            'summary': {
                'total_validated': 0,
                'confirmed': 0,
                'false_positives': 0,
                'needs_review': 0,
            },
        }

    # Split into batches
    batches = []
    for i in range(0, len(vulnerabilities), BATCH_SIZE):
        batches.append(vulnerabilities[i:i + BATCH_SIZE])

    logger.info(
        f"Validator Agent starting: {len(vulnerabilities)} vulnerabilities "
        f"in {len(batches)} batches, {max_workers} workers"
    )

    # Process batches (in parallel if multiple batches)
    all_validations = [None] * len(vulnerabilities)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_batch = {}
        for batch_idx, batch in enumerate(batches):
            future = executor.submit(validate_batch, batch, None)
            future_to_batch[future] = batch_idx

        for future in concurrent.futures.as_completed(future_to_batch):
            batch_idx = future_to_batch[future]
            batch_offset = batch_idx * BATCH_SIZE

            try:
                batch_validations = future.result()
                for j, validation in enumerate(batch_validations):
                    global_idx = batch_offset + j
                    if global_idx < len(vulnerabilities):
                        all_validations[global_idx] = validation

                logger.info(
                    f"Batch {batch_idx + 1}/{len(batches)} validated: "
                    f"{len(batch_validations)} results"
                )
            except Exception as e:
                logger.error(f"Batch {batch_idx} failed: {e}")
                # Fill with defaults
                batch_size = len(batches[batch_idx])
                for j in range(batch_size):
                    global_idx = batch_offset + j
                    if global_idx < len(vulnerabilities):
                        all_validations[global_idx] = _default_validation(j)

    # Fill any remaining None slots
    for i, v in enumerate(all_validations):
        if v is None:
            all_validations[i] = _default_validation(i)

    # Merge original vulnerability data with validation results
    validated_vulnerabilities = []
    status_counts = {'Confirmed': 0, 'False Positive': 0, 'Needs Human Review': 0}

    for vuln, validation in zip(vulnerabilities, all_validations):
        merged = {
            # Original fields from Detector
            'filepath': vuln.get('filepath', ''),
            'line_number': vuln.get('line_number', 0),
            'vulnerability_type': vuln.get('vulnerability_type', ''),
            'original_severity': vuln.get('severity', 'Medium'),
            'code_snippet': vuln.get('code_snippet', ''),
            'description': vuln.get('description', ''),
            'cwe_id': vuln.get('cwe_id', 'N/A'),
            # Validation fields from Validator
            'confidence_score': validation['confidence_score'],
            'status': validation['status'],
            'adjusted_severity': validation['adjusted_severity'],
            'validation_reasoning': validation['validation_reasoning'],
            'recommendation': validation['recommendation'],
        }
        validated_vulnerabilities.append(merged)
        status_counts[validation['status']] = status_counts.get(validation['status'], 0) + 1

    # Sort: Confirmed first (by severity), then Needs Review, then False Positive
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
    status_order = {'Confirmed': 0, 'Needs Human Review': 1, 'False Positive': 2}

    validated_vulnerabilities.sort(key=lambda v: (
        status_order.get(v['status'], 9),
        severity_order.get(v['adjusted_severity'], 9),
        v['filepath'],
    ))

    summary = {
        'total_validated': len(vulnerabilities),
        'confirmed': status_counts.get('Confirmed', 0),
        'false_positives': status_counts.get('False Positive', 0),
        'needs_review': status_counts.get('Needs Human Review', 0),
    }

    logger.info(
        f"Validator Agent complete: {summary['confirmed']} confirmed, "
        f"{summary['needs_review']} needs review, "
        f"{summary['false_positives']} false positives"
    )

    return {
        'validated_vulnerabilities': validated_vulnerabilities,
        'summary': summary,
    }
