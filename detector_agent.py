"""
Detector Agent Module (Sub-agent #1)
=====================================
Analyzes source code chunks for potential security vulnerabilities
using Google Gemini LLM. Designed for HIGH RECALL — it's better to
flag a false positive than to miss a real vulnerability.

The Validator Agent (Stage 3) will later filter out false positives.
"""

import json
import logging
import time
import concurrent.futures
from typing import List, Optional
import requests
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Maximum parallel api calls
MAX_WORKERS = 5

# Retry configuration for API rate limits
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2  # seconds, exponential backoff

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

# ---------------------------------------------------------------------------
# Detector System Prompt
# ---------------------------------------------------------------------------

DETECTOR_SYSTEM_PROMPT = """You are a Senior Application Security Engineer performing Static Application Security Testing (SAST).
Your role is the DETECTOR — your goal is to find ALL potential security vulnerabilities in the provided source code.

CRITICAL INSTRUCTION: Prioritize HIGH RECALL. It is far better to flag a suspicious code pattern that might be safe
than to miss a real vulnerability. False positives will be filtered by a separate Validator agent later.

VULNERABILITY CATEGORIES TO LOOK FOR:
1. SQL Injection (SQLi) — unsanitized user input in SQL queries, string concatenation in queries, raw queries without parameterization
2. Cross-Site Scripting (XSS) — unsanitized user input rendered in HTML/templates, innerHTML usage, document.write with user data
3. Path Traversal / Directory Traversal — user input used in file paths without sanitization, os.path.join with user input
4. Broken Access Control — missing authentication/authorization checks, IDOR patterns, privilege escalation paths
5. Insecure Deserialization — pickle.loads, yaml.load without SafeLoader, eval/exec with user data
6. Command Injection — os.system, subprocess with shell=True using user input, backtick execution
7. Sensitive Data Exposure — hardcoded secrets/API keys/passwords, sensitive data in logs, weak cryptography
8. Security Misconfiguration — debug mode in production, permissive CORS, missing security headers
9. Server-Side Request Forgery (SSRF) — user-controlled URLs in server-side requests
10. Broken Authentication — weak password hashing, missing brute-force protection, session fixation

RESPONSE FORMAT:
You MUST respond with a valid JSON array. Each element represents one potential vulnerability.
If no vulnerabilities are found, return an empty array: []

Each vulnerability object MUST have these exact fields:
{
  "line_number": <int>,           // Line number in the original file where the vulnerability is located
  "vulnerability_type": <string>, // One of: "SQL Injection", "XSS", "Path Traversal", "Broken Access Control",
                                  //         "Insecure Deserialization", "Command Injection", "Sensitive Data Exposure",
                                  //         "Security Misconfiguration", "SSRF", "Broken Authentication", "Other"
  "severity": <string>,           // One of: "Critical", "High", "Medium", "Low", "Info"
  "code_snippet": <string>,       // The exact vulnerable line(s) of code (max 3 lines)
  "description": <string>,        // Brief explanation of WHY this is potentially vulnerable (2-3 sentences max)
  "cwe_id": <string>              // CWE identifier if known (e.g., "CWE-89"), or "N/A"
}

IMPORTANT RULES:
- Return ONLY the JSON array, no markdown formatting, no code fences, no explanations outside the JSON.
- line_number must be relative to the CHUNK provided (the chunk metadata shows the original file line range).
- Be thorough but precise — flag real patterns, not theoretical risks.
- If code uses an ORM with parameterized queries, that's likely NOT SQL injection.
- If code uses template engines with auto-escaping (Jinja2, React JSX), lower severity but still flag if raw HTML is used.
"""

# ---------------------------------------------------------------------------
# Core detection functions
# ---------------------------------------------------------------------------

def _build_detector_prompt(chunk: dict) -> str:
    """
    Build the user prompt for a single code chunk.

    Args:
        chunk: Dict with keys: filepath, language, start_line, end_line,
               chunk_index, total_chunks, content
    """
    return f"""Analyze the following source code chunk for security vulnerabilities.

FILE METADATA:
- File: {chunk['filepath']}
- Language: {chunk['language']}
- Lines: {chunk['start_line']} to {chunk['end_line']}
- Chunk: {chunk['chunk_index'] + 1} of {chunk['total_chunks']}

SOURCE CODE:
```{chunk['language']}
{chunk['content']}
```

Return a JSON array of all potential vulnerabilities found. If none, return [].
"""


def analyze_chunk(chunk: dict, model=None) -> dict:
    """
    Send a single code chunk to Groq API for vulnerability detection.

    Args:
        chunk: Code chunk dictionary from sast_processor.
        model: Ignored. Maintained for compatibility.

    Returns:
        Dict with original chunk metadata + 'vulnerabilities' list.
    """
    user_prompt = _build_detector_prompt(chunk)

    vulnerabilities = []
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
                    {"role": "system", "content": DETECTOR_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.2
            }

            response = requests.post(DEEPSEEK_URL, headers=headers, json=payload, timeout=120)
            response.raise_for_status()

            # Parse response
            raw_text = response.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            vulnerabilities = _parse_detector_response(raw_text)

            # Adjust line numbers to be absolute (relative to original file)
            offset = chunk['start_line'] - 1
            for vuln in vulnerabilities:
                if isinstance(vuln.get('line_number'), int):
                    vuln['line_number'] += offset

            break  # Success — exit retry loop

        except Exception as e:
            last_error = str(e)
            logger.warning(
                f"Detector attempt {attempt + 1}/{MAX_RETRIES} failed for "
                f"{chunk['filepath']} chunk {chunk['chunk_index']}: {e}"
            )

            if attempt < MAX_RETRIES - 1:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                logger.info(f"Retrying in {delay}s...")
                time.sleep(delay)

    if last_error and not vulnerabilities:
        logger.error(
            f"All {MAX_RETRIES} attempts failed for {chunk['filepath']} "
            f"chunk {chunk['chunk_index']}: {last_error}"
        )

    return {
        'filepath': chunk['filepath'],
        'language': chunk['language'],
        'start_line': chunk['start_line'],
        'end_line': chunk['end_line'],
        'chunk_index': chunk['chunk_index'],
        'total_chunks': chunk['total_chunks'],
        'vulnerabilities': vulnerabilities,
        'error': last_error if (last_error and not vulnerabilities) else None,
    }


def _parse_detector_response(raw_text: str) -> list:
    """
    Parse the LLM response into a list of vulnerability dicts.

    Handles common LLM output quirks:
    - Markdown code fences around JSON
    - Extra text before/after JSON
    - Malformed JSON with trailing commas
    """
    # Strip markdown code fences if present
    text = raw_text
    if '```json' in text:
        text = text.split('```json', 1)[1]
        text = text.split('```', 1)[0]
    elif '```' in text:
        text = text.split('```', 1)[1]
        text = text.split('```', 1)[0]

    text = text.strip()

    # Try to find JSON array in the text
    if not text.startswith('['):
        # Try to find the array start
        bracket_pos = text.find('[')
        if bracket_pos != -1:
            text = text[bracket_pos:]
        else:
            # No array found — might be "no vulnerabilities" response
            logger.info("Detector returned no JSON array — interpreting as 0 vulnerabilities")
            return []

    # Find matching closing bracket
    if not text.endswith(']'):
        last_bracket = text.rfind(']')
        if last_bracket != -1:
            text = text[:last_bracket + 1]

    # Remove trailing commas before ] (common LLM mistake)
    text = text.replace(',]', ']').replace(',\n]', '\n]')

    try:
        result = json.loads(text)
        if isinstance(result, list):
            # Validate each vulnerability has required fields
            validated = []
            for item in result:
                if isinstance(item, dict) and 'vulnerability_type' in item:
                    validated.append(_normalize_vulnerability(item))
            return validated
        else:
            logger.warning(f"Detector returned non-array JSON: {type(result)}")
            return []
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse detector response as JSON: {e}")
        logger.debug(f"Raw text was: {text[:500]}")
        return []


def _normalize_vulnerability(vuln: dict) -> dict:
    """Ensure all required fields exist with correct types."""
    return {
        'line_number': int(vuln.get('line_number', 0)),
        'vulnerability_type': str(vuln.get('vulnerability_type', 'Other')),
        'severity': str(vuln.get('severity', 'Medium')),
        'code_snippet': str(vuln.get('code_snippet', '')),
        'description': str(vuln.get('description', '')),
        'cwe_id': str(vuln.get('cwe_id', 'N/A')),
    }


# ---------------------------------------------------------------------------
# Parallel processing orchestrator
# ---------------------------------------------------------------------------

def run_detector(chunks: List[dict], max_workers: int = MAX_WORKERS) -> dict:
    """
    Process all code chunks through the Detector Agent in parallel.

    Uses ThreadPoolExecutor to send chunks to Ollama concurrently,
    respecting rate limits via MAX_WORKERS.

    Args:
        chunks: List of code chunk dicts from sast_processor.
        max_workers: Max parallel API calls.

    Returns:
        Dict with:
          - results: list of per-chunk results with vulnerabilities
          - summary: aggregate statistics
    """
    results = []
    total_vulns = 0
    errors = 0
    severity_counts = {
        'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0
    }
    vuln_type_counts = {}

    logger.info(f"Detector Agent starting: {len(chunks)} chunks, {max_workers} workers")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all chunks for analysis
        future_to_chunk = {
            executor.submit(analyze_chunk, chunk, None): idx
            for idx, chunk in enumerate(chunks)
        }

        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_chunk):
            chunk_idx = future_to_chunk[future]
            try:
                result = future.result()
                results.append(result)

                # Update statistics
                chunk_vulns = result.get('vulnerabilities', [])
                total_vulns += len(chunk_vulns)

                if result.get('error'):
                    errors += 1

                for vuln in chunk_vulns:
                    sev = vuln.get('severity', 'Medium')
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1

                    vtype = vuln.get('vulnerability_type', 'Other')
                    vuln_type_counts[vtype] = vuln_type_counts.get(vtype, 0) + 1

                logger.info(
                    f"Chunk {chunk_idx + 1}/{len(chunks)} done: "
                    f"{len(chunk_vulns)} potential vulnerabilities"
                )

            except Exception as e:
                errors += 1
                logger.error(f"Chunk {chunk_idx} raised exception: {e}")
                results.append({
                    'filepath': chunks[chunk_idx].get('filepath', 'unknown'),
                    'chunk_index': chunk_idx,
                    'vulnerabilities': [],
                    'error': str(e),
                })

    # Sort results by file path and chunk index for consistent ordering
    results.sort(key=lambda r: (r.get('filepath', ''), r.get('chunk_index', 0)))

    # Deduplicate vulnerabilities that may appear in overlapping chunks
    all_vulnerabilities = _deduplicate_vulnerabilities(results)

    summary = {
        'total_chunks_analyzed': len(chunks),
        'total_vulnerabilities': len(all_vulnerabilities),
        'chunks_with_errors': errors,
        'severity_breakdown': severity_counts,
        'vulnerability_types': vuln_type_counts,
    }

    logger.info(
        f"Detector Agent complete: {len(all_vulnerabilities)} potential vulnerabilities "
        f"found across {len(chunks)} chunks ({errors} errors)"
    )

    return {
        'results': results,
        'vulnerabilities': all_vulnerabilities,
        'summary': summary,
    }


def _deduplicate_vulnerabilities(results: list) -> list:
    """
    Remove duplicate vulnerabilities from overlapping chunks.

    Two vulnerabilities are considered duplicates if they have the same
    file, line number, and vulnerability type.
    """
    seen = set()
    unique = []

    for result in results:
        for vuln in result.get('vulnerabilities', []):
            # Create a dedup key
            key = (
                result.get('filepath', ''),
                vuln.get('line_number', 0),
                vuln.get('vulnerability_type', ''),
            )

            if key not in seen:
                seen.add(key)
                vuln_with_file = {**vuln, 'filepath': result.get('filepath', '')}
                unique.append(vuln_with_file)

    return unique
