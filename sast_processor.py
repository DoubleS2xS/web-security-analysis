"""
SAST Processor Module
=====================
Handles source code ingestion for the SAST pipeline:
- Downloading repos from GitHub (public)
- Extracting uploaded ZIP archives
- Filtering source code files (whitelist extensions, blacklist dirs)
- Chunking large files for LLM context windows
"""

import os
import re
import uuid
import shutil
import zipfile
import tempfile
import logging
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Base directory for temporary uploads (relative to project root)
UPLOAD_BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

# Maximum upload size in bytes (50 MB)
MAX_UPLOAD_SIZE = 50 * 1024 * 1024

# Maximum number of source files to process
MAX_FILES = 500

# Chunking parameters
MAX_CHUNK_CHARS = 12000   # ~3000 tokens (1 token ≈ 4 chars)
OVERLAP_LINES = 20        # lines of overlap between adjacent chunks

# File extensions considered as source code
ALLOWED_EXTENSIONS = {
    # Python
    '.py',
    # JavaScript / TypeScript
    '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
    # Java / Kotlin
    '.java', '.kt', '.kts',
    # PHP
    '.php',
    # Ruby
    '.rb',
    # Go
    '.go',
    # C / C++
    '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx',
    # C#
    '.cs',
    # Swift
    '.swift',
    # Rust
    '.rs',
    # Web / Markup
    '.html', '.htm', '.xml', '.svg',
    # SQL
    '.sql',
    # Shell
    '.sh', '.bash',
    # Config (may contain secrets / misconfigurations)
    '.yml', '.yaml', '.json', '.env', '.cfg', '.ini', '.conf', '.toml',
}

# Directories to skip during traversal
IGNORED_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv', 'env',
    'vendor', 'dist', 'build', '.idea', '.vscode',
    'target', 'bin', 'obj', '.gradle', '.mvn',
    '.next', '.nuxt', 'coverage', '.tox', '.mypy_cache',
    '.pytest_cache', 'eggs', '*.egg-info',
}

# Map file extensions to language names (for metadata)
EXTENSION_TO_LANGUAGE = {
    '.py': 'python', '.pyw': 'python',
    '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.ts': 'typescript', '.tsx': 'typescript',
    '.jsx': 'javascript',
    '.java': 'java',
    '.kt': 'kotlin', '.kts': 'kotlin',
    '.php': 'php',
    '.rb': 'ruby',
    '.go': 'go',
    '.c': 'c', '.h': 'c',
    '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp', '.hxx': 'cpp',
    '.cs': 'csharp',
    '.swift': 'swift',
    '.rs': 'rust',
    '.html': 'html', '.htm': 'html',
    '.xml': 'xml', '.svg': 'xml',
    '.sql': 'sql',
    '.sh': 'shell', '.bash': 'shell',
    '.yml': 'yaml', '.yaml': 'yaml',
    '.json': 'json',
    '.env': 'dotenv',
    '.cfg': 'config', '.ini': 'config', '.conf': 'config', '.toml': 'toml',
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CodeChunk:
    """Represents a chunk of source code ready for LLM analysis."""
    filepath: str          # relative path from project root
    language: str          # detected language
    start_line: int        # 1-indexed
    end_line: int          # 1-indexed, inclusive
    chunk_index: int       # 0-indexed chunk number within file
    total_chunks: int      # total chunks for this file
    content: str           # the actual source code

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# GitHub download
# ---------------------------------------------------------------------------

def _parse_github_url(url: str) -> Tuple[str, str, str]:
    """
    Parse a GitHub URL into (owner, repo, branch).
    Supports:
      - https://github.com/owner/repo
      - https://github.com/owner/repo/tree/branch
    Returns (owner, repo, branch). Branch defaults to 'main'.
    """
    url = url.rstrip('/')

    # Pattern: github.com/owner/repo/tree/branch
    match = re.match(
        r'https?://github\.com/([^/]+)/([^/]+)/tree/(.+)', url
    )
    if match:
        return match.group(1), match.group(2), match.group(3)

    # Pattern: github.com/owner/repo
    match = re.match(
        r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?$', url
    )
    if match:
        return match.group(1), match.group(2), 'main'

    raise ValueError(f"Invalid GitHub URL format: {url}")


def download_github_repo(github_url: str) -> str:
    """
    Download a public GitHub repository as ZIP and extract it.

    Args:
        github_url: Public GitHub repository URL.

    Returns:
        Path to the extracted project root directory.

    Raises:
        ValueError: If URL is invalid or repo is not accessible.
    """
    owner, repo, branch = _parse_github_url(github_url)

    # Create unique upload directory
    upload_id = str(uuid.uuid4())[:8]
    upload_dir = os.path.join(UPLOAD_BASE_DIR, upload_id)
    os.makedirs(upload_dir, exist_ok=True)

    zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
    logger.info(f"Downloading GitHub repo: {zip_url}")

    try:
        response = requests.get(zip_url, stream=True, timeout=60)

        # If 'main' branch fails, try 'master'
        if response.status_code == 404 and branch == 'main':
            branch = 'master'
            zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
            logger.info(f"Retrying with 'master' branch: {zip_url}")
            response = requests.get(zip_url, stream=True, timeout=60)

        if response.status_code != 200:
            cleanup_upload(upload_dir)
            raise ValueError(
                f"Failed to download repository. HTTP {response.status_code}. "
                f"Make sure the repository is public and the URL is correct."
            )

        # Check content length if available
        content_length = response.headers.get('Content-Length')
        if content_length and int(content_length) > MAX_UPLOAD_SIZE:
            cleanup_upload(upload_dir)
            raise ValueError(
                f"Repository archive is too large ({int(content_length) // (1024*1024)} MB). "
                f"Maximum allowed size is {MAX_UPLOAD_SIZE // (1024*1024)} MB."
            )

        # Save ZIP to temp file
        zip_path = os.path.join(upload_dir, 'repo.zip')
        downloaded_size = 0
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                downloaded_size += len(chunk)
                if downloaded_size > MAX_UPLOAD_SIZE:
                    cleanup_upload(upload_dir)
                    raise ValueError(
                        f"Repository archive exceeds maximum size of "
                        f"{MAX_UPLOAD_SIZE // (1024*1024)} MB."
                    )
                f.write(chunk)

        # Extract ZIP
        project_root = _safe_extract_zip(zip_path, upload_dir)

        # Remove the zip file after extraction
        os.remove(zip_path)

        return project_root

    except requests.RequestException as e:
        cleanup_upload(upload_dir)
        raise ValueError(f"Network error while downloading repository: {str(e)}")


# ---------------------------------------------------------------------------
# ZIP upload handling
# ---------------------------------------------------------------------------

def extract_uploaded_zip(file_storage) -> str:
    """
    Extract an uploaded ZIP file (Flask FileStorage object).

    Args:
        file_storage: Flask FileStorage object from request.files.

    Returns:
        Path to the extracted project root directory.

    Raises:
        ValueError: If file is invalid, too large, or not a ZIP.
    """
    # Create unique upload directory
    upload_id = str(uuid.uuid4())[:8]
    upload_dir = os.path.join(UPLOAD_BASE_DIR, upload_id)
    os.makedirs(upload_dir, exist_ok=True)

    # Save uploaded file
    zip_path = os.path.join(upload_dir, 'upload.zip')

    try:
        file_storage.save(zip_path)

        # Check file size
        file_size = os.path.getsize(zip_path)
        if file_size > MAX_UPLOAD_SIZE:
            cleanup_upload(upload_dir)
            raise ValueError(
                f"Uploaded file is too large ({file_size // (1024*1024)} MB). "
                f"Maximum allowed size is {MAX_UPLOAD_SIZE // (1024*1024)} MB."
            )

        # Validate it's actually a ZIP
        if not zipfile.is_zipfile(zip_path):
            cleanup_upload(upload_dir)
            raise ValueError("Uploaded file is not a valid ZIP archive.")

        # Extract
        project_root = _safe_extract_zip(zip_path, upload_dir)

        # Remove the zip after extraction
        os.remove(zip_path)

        return project_root

    except ValueError:
        raise
    except Exception as e:
        cleanup_upload(upload_dir)
        raise ValueError(f"Error processing uploaded ZIP: {str(e)}")


def _safe_extract_zip(zip_path: str, extract_to: str) -> str:
    """
    Safely extract a ZIP file with path traversal protection.

    Returns the project root directory (handles single top-level dir case).
    """
    with zipfile.ZipFile(zip_path, 'r') as zf:
        # Security: check for path traversal attacks
        for member in zf.namelist():
            member_path = os.path.realpath(os.path.join(extract_to, member))
            extract_to_real = os.path.realpath(extract_to)

            if not member_path.startswith(extract_to_real + os.sep) and member_path != extract_to_real:
                raise ValueError(
                    f"ZIP contains path traversal attempt: {member}. "
                    f"Archive rejected for security reasons."
                )

        zf.extractall(extract_to)

    # GitHub ZIPs typically have a single top-level directory like "repo-main/"
    # Detect this and return the actual project root
    extracted_items = [
        item for item in os.listdir(extract_to)
        if item not in ('repo.zip', 'upload.zip')
    ]

    if len(extracted_items) == 1:
        single_dir = os.path.join(extract_to, extracted_items[0])
        if os.path.isdir(single_dir):
            return single_dir

    return extract_to


# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------

def filter_source_files(root_dir: str) -> List[str]:
    """
    Recursively find all source code files in a directory.

    Filters by ALLOWED_EXTENSIONS and skips IGNORED_DIRS.

    Args:
        root_dir: Root directory to search.

    Returns:
        List of absolute file paths to source files.
    """
    source_files = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Modify dirnames in-place to skip ignored directories
        dirnames[:] = [
            d for d in dirnames
            if d not in IGNORED_DIRS and not d.startswith('.')
        ]

        for filename in filenames:
            # Check extension
            _, ext = os.path.splitext(filename)
            if ext.lower() in ALLOWED_EXTENSIONS:
                filepath = os.path.join(dirpath, filename)

                # Skip very large files (> 1 MB — likely generated/minified)
                try:
                    if os.path.getsize(filepath) > 1 * 1024 * 1024:
                        logger.warning(f"Skipping large file (>1MB): {filepath}")
                        continue
                except OSError:
                    continue

                source_files.append(filepath)

                if len(source_files) >= MAX_FILES:
                    logger.warning(
                        f"File limit reached ({MAX_FILES}). "
                        f"Some files may not be analyzed."
                    )
                    return source_files

    return source_files


def _detect_language(filepath: str) -> str:
    """Detect programming language from file extension."""
    _, ext = os.path.splitext(filepath)
    return EXTENSION_TO_LANGUAGE.get(ext.lower(), 'unknown')


# ---------------------------------------------------------------------------
# Code chunking
# ---------------------------------------------------------------------------

def chunk_file(filepath: str, max_chars: int = MAX_CHUNK_CHARS,
               overlap_lines: int = OVERLAP_LINES) -> List[dict]:
    """
    Split a source file into chunks suitable for LLM processing.

    Strategy:
    - Read file as lines
    - Build chunks of up to max_chars characters
    - Maintain overlap_lines of overlap between consecutive chunks
    - Each chunk includes metadata (line numbers, index)

    Args:
        filepath: Absolute path to the source file.
        max_chars: Maximum number of characters per chunk.
        overlap_lines: Number of overlapping lines between chunks.

    Returns:
        List of dicts with chunk metadata and content.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except (IOError, OSError) as e:
        logger.error(f"Cannot read file {filepath}: {e}")
        return []

    if not lines:
        return []

    total_lines = len(lines)
    chunks_raw = []

    current_start = 0  # 0-indexed line index

    while current_start < total_lines:
        # Build chunk content from current_start
        chunk_content = ""
        current_end = current_start

        for i in range(current_start, total_lines):
            line = lines[i]
            if len(chunk_content) + len(line) > max_chars and i > current_start:
                # This line would exceed the limit — stop before it
                break
            chunk_content += line
            current_end = i

        chunks_raw.append({
            'start_line': current_start + 1,   # convert to 1-indexed
            'end_line': current_end + 1,        # convert to 1-indexed
            'content': chunk_content,
        })

        # Move start forward, accounting for overlap
        next_start = current_end + 1 - overlap_lines
        if next_start <= current_start:
            # Avoid infinite loop: always advance at least 1 line past the chunk
            next_start = current_end + 1

        current_start = next_start

    return chunks_raw


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def process_upload(source, source_type: str) -> dict:
    """
    Main orchestrator: ingest source code and produce chunks.

    Args:
        source: Either a Flask FileStorage (for ZIP) or a string (GitHub URL).
        source_type: 'zip' or 'github'.

    Returns:
        Dict with:
          - upload_dir: path to temp directory (caller must cleanup)
          - stats: {total_files, total_chunks, languages}
          - chunks: List[CodeChunk] as dicts
    """
    # Step 1: Download / Extract
    if source_type == 'github':
        project_root = download_github_repo(source)
    elif source_type == 'zip':
        project_root = extract_uploaded_zip(source)
    else:
        raise ValueError(f"Unsupported source type: {source_type}")

    # Determine upload_dir from project_root
    # upload_dir is always inside UPLOAD_BASE_DIR
    upload_dir = project_root
    while os.path.dirname(upload_dir) != UPLOAD_BASE_DIR and upload_dir != '/':
        parent = os.path.dirname(upload_dir)
        if parent == upload_dir:
            break
        upload_dir = parent

    # Step 2: Filter source files
    source_files = filter_source_files(project_root)

    if not source_files:
        cleanup_upload(upload_dir)
        raise ValueError(
            "No source code files found in the uploaded project. "
            "Make sure the archive contains files with supported extensions "
            f"({', '.join(sorted(list(ALLOWED_EXTENSIONS)[:10]))}...)."
        )

    # Step 3: Chunk each file
    all_chunks = []
    language_stats = {}

    for filepath in source_files:
        relative_path = os.path.relpath(filepath, project_root)
        language = _detect_language(filepath)

        # Update language stats
        language_stats[language] = language_stats.get(language, 0) + 1

        # Chunk the file
        raw_chunks = chunk_file(filepath)

        if not raw_chunks:
            continue

        total_chunks_for_file = len(raw_chunks)

        for idx, raw_chunk in enumerate(raw_chunks):
            chunk = CodeChunk(
                filepath=relative_path,
                language=language,
                start_line=raw_chunk['start_line'],
                end_line=raw_chunk['end_line'],
                chunk_index=idx,
                total_chunks=total_chunks_for_file,
                content=raw_chunk['content'],
            )
            all_chunks.append(chunk)

    result = {
        'upload_dir': upload_dir,
        'stats': {
            'total_files': len(source_files),
            'total_chunks': len(all_chunks),
            'languages': language_stats,
        },
        'chunks': [chunk.to_dict() for chunk in all_chunks],
    }

    logger.info(
        f"Processed {result['stats']['total_files']} files into "
        f"{result['stats']['total_chunks']} chunks. "
        f"Languages: {language_stats}"
    )

    return result


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def cleanup_upload(upload_dir: str):
    """
    Remove temporary upload directory and all its contents.

    Args:
        upload_dir: Path to the upload directory to remove.
    """
    if not upload_dir:
        return

    # Safety: only delete dirs inside UPLOAD_BASE_DIR
    real_upload_dir = os.path.realpath(upload_dir)
    real_base = os.path.realpath(UPLOAD_BASE_DIR)

    if not real_upload_dir.startswith(real_base + os.sep):
        logger.error(
            f"Refusing to delete directory outside uploads base: {upload_dir}"
        )
        return

    try:
        shutil.rmtree(upload_dir)
        logger.info(f"Cleaned up upload directory: {upload_dir}")
    except OSError as e:
        logger.error(f"Failed to clean up {upload_dir}: {e}")
