"""Repository ingestion using gitingest."""

from typing import Dict, Optional, Tuple

import click
from gitingest import ingest


def ingest_repo(repo_path: str) -> Tuple[Dict, str, str]:
    """Ingest a local repository and return its content as a text blob.

    Args:
        repo_path: Path to the local repository directory.

    Returns:
        A tuple of (summary, tree, content) where:
        - summary: dict with file_count and total_size stats
        - tree: directory tree string
        - content: full text blob of the repo

    Raises:
        Exception: If gitingest fails to process the repository.
    """
    summary, tree, content = ingest(repo_path)

    # Check if content was truncated (gitingest may truncate large repos)
    if hasattr(summary, "get") and summary.get("truncated"):
        click.echo("      Warning: Repository content was truncated due to size limits.")

    # Parse summary - gitingest returns an IngestionResult object or similar
    if isinstance(summary, str):
        # Try to extract stats from summary string
        summary_dict = {
            "file_count": "unknown",
            "total_size": "unknown",
        }
        # gitingest summary format varies, try to parse common patterns
        if "files" in summary.lower():
            parts = summary.split()
            for i, part in enumerate(parts):
                if part.isdigit() and i + 1 < len(parts) and "file" in parts[i + 1].lower():
                    summary_dict["file_count"] = part
                    break
        summary = summary_dict
    elif hasattr(summary, "total_files"):
        # gitingest IngestionResult object
        file_count = getattr(summary, "total_files", "unknown")
        total_size = getattr(summary, "total_size", 0)
        # Format size nicely
        if isinstance(total_size, int):
            if total_size > 1024 * 1024:
                size_str = f"{total_size / (1024 * 1024):.1f} MB"
            elif total_size > 1024:
                size_str = f"{total_size / 1024:.1f} KB"
            else:
                size_str = f"{total_size} bytes"
        else:
            size_str = str(total_size)
        summary = {
            "file_count": file_count,
            "total_size": size_str,
        }
    elif not isinstance(summary, dict):
        summary = {
            "file_count": "unknown",
            "total_size": "unknown",
        }

    return summary, tree, content


def extract_file_content(full_content: str, file_path: str) -> Optional[str]:
    """Extract a single file's content from the gitingest output.

    The gitingest output contains all files concatenated with delimiters like:
    ================================================
    FILE: path/to/file.py
    ================================================
    <file content>

    Args:
        full_content: The full content blob from gitingest.
        file_path: The file path to extract.

    Returns:
        The file content if found, None otherwise.
    """
    # Gitingest uses this format:
    # ================================================
    # FILE: path/to/file.py
    # ================================================
    file_marker = f"FILE: {file_path}"
    
    if file_marker in full_content:
        # Find the start of this file's marker
        marker_idx = full_content.find(file_marker)
        if marker_idx == -1:
            return None
        
        # Move past the FILE: line and the following === line
        content_start = full_content.find("\n", marker_idx)
        if content_start == -1:
            return None
        content_start += 1
        
        # Skip the closing === delimiter line
        if full_content[content_start:].startswith("="):
            content_start = full_content.find("\n", content_start)
            if content_start == -1:
                return None
            content_start += 1
        
        # Find the next file delimiter (starts with ===...followed by FILE:)
        next_file_idx = full_content.find("\n================================================\nFILE:", content_start)
        if next_file_idx == -1:
            # No more files, take until end
            return full_content[content_start:].strip()
        else:
            return full_content[content_start:next_file_idx].strip()
    
    # Try alternative delimiters for backwards compatibility
    alt_delimiters = [
        f"--- File: {file_path} ---",
        f"--- {file_path} ---",
        f"File: {file_path}",
    ]
    
    for delimiter in alt_delimiters:
        if delimiter in full_content:
            start_idx = full_content.find(delimiter)
            if start_idx == -1:
                continue
            
            content_start = full_content.find("\n", start_idx)
            if content_start == -1:
                continue
            content_start += 1
            
            # Find next delimiter
            next_file_patterns = ["--- File:", "---\n", "\n================================================\n"]
            end_idx = len(full_content)
            
            for pattern in next_file_patterns:
                next_idx = full_content.find(pattern, content_start)
                if next_idx != -1 and next_idx < end_idx:
                    if next_idx > content_start:
                        end_idx = next_idx
            
            return full_content[content_start:end_idx].strip()
    
    return None
