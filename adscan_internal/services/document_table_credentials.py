"""Table-aware credential pre-extraction for PDF/XLSX/DOCX documents.

CredSweeper misses credentials that live in document TABLES. Its per-format
extractors flatten a table so a secret cell (``R3dT3am@Acc3ss#01``) is scanned
in isolation from its label cell (``Password``), while CredSweeper's rules are
line-based and need the key and value together on one line joined by ``:`` or
``=``. A password sitting in a table cell therefore reads as an anonymous token
and is dropped.

This module reads a document's TABLES per format, reconstructs each row into
``key: value`` lines, and hands that reconstructed text to CredSweeper so the
line-based rules fire. It is modeled on CredSweeper's own HTML table handler
(``data_content_provider._table_representation``), which already pairs each cell
with its column header for HTML; this generalizes that proven approach to the
three document formats ADscan scans off SMB shares.

The layer only ADDS coverage: the caller still runs CredSweeper's own document
scan, then merges these table-derived findings and deduplicates. Nothing in the
existing scan path is replaced.

Format handling:
    - PDF  -> ``pdfplumber`` (MIT). Not pymupdf/fitz (AGPL, license-incompatible).
    - XLSX -> ``openpyxl`` (already a dependency via CredSweeper).
    - DOCX -> ``python-docx`` (already a dependency).
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, List, Optional, Sequence, Union

# A cell whose header names one of these is a credential column: pair values in
# that column with their own header. Deliberately excludes generic table labels
# such as ``Field``/``Value``/``Name``/``Description`` so a ``Field | Value``
# reference table is NOT paired as ``Value: <secret>`` (which CredSweeper's ML
# scores far lower than ``Password: <secret>``); those tables fall to the
# col0:col1 path where the real key column drives detection.
CREDENTIAL_HEADER_KEYWORDS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "key",
        "credential",
    }
)

# Reconstruction MUST join a key and its value with ``:`` (or ``=``). Measured
# against CredSweeper: its rules do not fire on tab / pipe / multiple-space /
# comma joins. Do not change this to another separator without re-measuring.
_KEY_VALUE_SEPARATOR = ": "

_SUPPORTED_SUFFIXES: frozenset[str] = frozenset({".pdf", ".xlsx", ".docx"})

# A Table is a list of rows; each row is a list of cell strings.
Table = List[List[str]]


def is_table_reconstruction_candidate(file_path: str | Path) -> bool:
    """Return whether a path is a format this layer can reconstruct tables from."""
    return Path(file_path).suffix.lower() in _SUPPORTED_SUFFIXES


def _normalize_cell(cell: object) -> str:
    """Return a whitespace-collapsed string for one raw table cell."""
    if cell is None:
        return ""
    text = str(cell)
    return " ".join(text.split()).strip()


def _header_names_credential(header_cell: str) -> bool:
    """Return whether a header cell names a credential column."""
    normalized = header_cell.strip().lower()
    if not normalized:
        return False
    if normalized in CREDENTIAL_HEADER_KEYWORDS:
        return True
    # Tolerate multi-word headers such as "Service Password" or "API Key".
    tokens = set(normalized.replace("-", " ").replace("_", " ").split())
    return bool(tokens & CREDENTIAL_HEADER_KEYWORDS)


def reconstruct_table_lines(rows: Sequence[Sequence[object]]) -> List[str]:
    """Reconstruct one table into ``key: value`` lines for CredSweeper.

    The heuristic:

    1. If the header row (first non-empty row) has at least one credential
       keyword header, pair EACH data cell with its OWN column header and keep
       the row's cells together on one emitted line (so a username pairs with
       the password on its row). This lets multi-column ``Domain | Username |
       Password`` and multi-row ``Username | Password`` tables detect.
    2. Otherwise (``Field | Value`` tables, row-label|value tables, or any table
       whose header is not a credential keyword) emit ``col0: col1`` per row, so
       the real key column drives detection and a ``Value`` header is never
       treated as a credential label.

    Args:
        rows: Raw table rows (each a sequence of cells) as returned by the
            per-format extractor.

    Returns:
        Reconstructed ``key: value`` lines. Empty when the table carries no
        usable key/value pair.
    """
    normalized: List[List[str]] = []
    for row in rows:
        cells = [_normalize_cell(cell) for cell in row]
        if any(cells):
            normalized.append(cells)
    if not normalized:
        return []

    header = normalized[0]
    header_has_credential = any(_header_names_credential(cell) for cell in header)

    lines: List[str] = []
    if header_has_credential and len(normalized) > 1:
        # Path 1: header-keyword-gated pairing. Each data cell -> "header: cell",
        # the whole row on one line so user and password stay together.
        for row in normalized[1:]:
            pairs: List[str] = []
            for index, cell in enumerate(row):
                if not cell:
                    continue
                header_cell = header[index] if index < len(header) else f"col{index}"
                if not header_cell:
                    header_cell = f"col{index}"
                pairs.append(f"{header_cell}{_KEY_VALUE_SEPARATOR}{cell}")
            if pairs:
                lines.append(" ".join(pairs))
    else:
        # Path 2: col0 is the key, col1 is the value. Applies to Field|Value and
        # any non-credential-header table. Extra columns beyond col1 are ignored
        # here; the key/value pair is what the line-based rules need.
        for row in normalized:
            if len(row) < 2:
                continue
            key, value = row[0], row[1]
            if key and value:
                lines.append(f"{key}{_KEY_VALUE_SEPARATOR}{value}")
    return lines


# A document source is either a filesystem path or a seekable binary stream
# (an in-memory ``BytesIO`` for byte-payload scanning). pdfplumber, openpyxl and
# python-docx all accept a file-like object as well as a path.
DocumentSource = Union[str, Path, BinaryIO]


def _resolve_opener(source: DocumentSource) -> object:
    """Return a path string or the file-like object the readers accept."""
    return str(source) if isinstance(source, (str, Path)) else source


def _extract_pdf_tables(source: DocumentSource) -> List[Table]:
    """Extract tables from a PDF via pdfplumber, gated by a cheap has-tables probe.

    ``page.find_tables()`` only locates table boundaries and is much cheaper than
    ``page.extract_tables()`` (which groups every cell). On a document with no
    tables the probe short-circuits and the expensive cell grouping never runs,
    so a no-table PDF pays only the probe.
    """
    import pdfplumber  # lazy: only imported when a PDF is actually scanned  # pylint: disable=import-error

    tables: List[Table] = []
    with pdfplumber.open(_resolve_opener(source)) as pdf:
        for page in pdf.pages:
            if not page.find_tables():
                continue
            for table in page.extract_tables() or []:
                tables.append([list(row) for row in table])
    return tables


def _extract_xlsx_tables(source: DocumentSource) -> List[Table]:
    """Extract each worksheet of an XLSX as one table via openpyxl.

    A worksheet is only extracted when at least one of its first rows has two or
    more populated cells (a key/value shape). ``read_only`` streaming means an
    empty or single-column sheet is skipped after reading only a few rows, not
    the whole sheet.
    """
    from openpyxl import load_workbook  # lazy import

    workbook = load_workbook(filename=_resolve_opener(source), read_only=True, data_only=True)
    try:
        tables: List[Table] = []
        for worksheet in workbook.worksheets:
            rows = [
                [cell for cell in row]
                for row in worksheet.iter_rows(values_only=True)
            ]
            if _rows_have_key_value_shape(rows):
                tables.append(rows)  # type: ignore[arg-type]
        return tables
    finally:
        workbook.close()


def _extract_docx_tables(source: DocumentSource) -> List[Table]:
    """Extract tables from a DOCX via python-docx.

    ``document.tables`` is already parsed on open, so probing it is cheap; only
    the per-cell text is read for tables that exist.
    """
    from docx import Document  # lazy import

    document = Document(_resolve_opener(source))
    tables: List[Table] = []
    for table in document.tables:
        rows: Table = []
        for row in table.rows:
            rows.append([cell.text for cell in row.cells])
        if rows:
            tables.append(rows)
    return tables


def _rows_have_key_value_shape(rows: Sequence[Sequence[object]]) -> bool:
    """Return whether any of the first rows has two or more populated cells."""
    for row in rows[:8]:
        populated = sum(1 for cell in row if str(cell if cell is not None else "").strip())
        if populated >= 2:
            return True
    return False


def _has_pdf_tables(source: DocumentSource) -> bool:
    """Cheap has-tables probe for a PDF (``find_tables``, no cell grouping)."""
    import pdfplumber  # lazy import  # pylint: disable=import-error

    with pdfplumber.open(_resolve_opener(source)) as pdf:
        for page in pdf.pages:
            if page.find_tables():
                return True
    return False


def _has_xlsx_tables(source: DocumentSource) -> bool:
    """Cheap has-tables probe for an XLSX (first rows carry a key/value shape)."""
    from openpyxl import load_workbook  # lazy import

    workbook = load_workbook(filename=_resolve_opener(source), read_only=True, data_only=True)
    try:
        for worksheet in workbook.worksheets:
            for index, row in enumerate(worksheet.iter_rows(values_only=True)):
                if _rows_have_key_value_shape([row]):
                    return True
                if index >= 8:
                    break
        return False
    finally:
        workbook.close()


def _has_docx_tables(source: DocumentSource) -> bool:
    """Cheap has-tables probe for a DOCX (``document.tables`` is parsed on open)."""
    from docx import Document  # lazy import

    return len(Document(_resolve_opener(source)).tables) > 0


_EXTRACTORS: dict[str, Callable[[DocumentSource], List[Table]]] = {
    ".pdf": _extract_pdf_tables,
    ".xlsx": _extract_xlsx_tables,
    ".docx": _extract_docx_tables,
}

_TABLE_PROBES: dict[str, Callable[[DocumentSource], bool]] = {
    ".pdf": _has_pdf_tables,
    ".xlsx": _has_xlsx_tables,
    ".docx": _has_docx_tables,
}


def document_has_tables(source: DocumentSource, *, suffix: str) -> bool:
    """Run the cheap per-format has-tables probe for one document source.

    Args:
        source: A path or a seekable binary stream.
        suffix: The document's normalized ``.ext`` (``.pdf``/``.xlsx``/``.docx``).

    Returns:
        ``True`` only when the format is supported and the probe finds a table.
        Best-effort: any probe error returns ``False`` (never raises), so a file
        that cannot be probed is simply not augmented.
    """
    probe = _TABLE_PROBES.get(_normalize_suffix(suffix))
    if probe is None:
        return False
    try:
        return probe(source)
    except Exception:  # noqa: BLE001 - probe is best-effort; a failure skips augmentation
        return False


def _normalize_suffix(file_path_or_type: str) -> str:
    """Return a normalized ``.ext`` for a path or a bare/`.`-prefixed type token."""
    token = str(file_path_or_type or "").strip().lower()
    if not token:
        return ""
    suffix = Path(token).suffix
    if suffix:
        return suffix
    return token if token.startswith(".") else f".{token}"


def extract_document_tables(file_path: str | Path) -> List[Table]:
    """Extract raw tables from a supported document.

    Args:
        file_path: Path to a ``.pdf``, ``.xlsx`` or ``.docx`` file.

    Returns:
        A list of tables (each a list of rows of cell strings). Empty for an
        unsupported extension or a document with no tables.
    """
    path = Path(file_path)
    extractor = _EXTRACTORS.get(path.suffix.lower())
    if extractor is None:
        return []
    if not path.is_file():
        return []
    return extractor(path)


def _lines_to_text(lines: List[str]) -> Optional[str]:
    """Join reconstructed lines, or ``None`` when there is nothing to scan."""
    if not lines:
        return None
    return "\n".join(lines)


def reconstruct_document_table_text(file_path: str | Path) -> Optional[str]:
    """Return reconstructed ``key: value`` text for a document's tables.

    Args:
        file_path: Path to a supported document.

    Returns:
        The reconstructed text (newline-joined ``key: value`` lines), or ``None``
        when the document is unsupported, has no tables, or yields no usable
        key/value pair.
    """
    tables = extract_document_tables(file_path)
    lines: List[str] = []
    for table in tables:
        lines.extend(reconstruct_table_lines(table))
    return _lines_to_text(lines)


def reconstruct_document_table_text_from_bytes(
    data: bytes,
    *,
    file_type: str,
) -> Optional[str]:
    """Return reconstructed ``key: value`` text from in-memory document bytes.

    This mirrors :func:`reconstruct_document_table_text` for the byte-payload
    scan path (``CredSweeperLibraryService``), where the document is only
    available as bytes and a logical file type rather than a disk path.

    Args:
        data: Raw document bytes.
        file_type: File extension or type token (``pdf``/``.pdf``/``x.pdf``).

    Returns:
        Reconstructed text, or ``None`` when the type is unsupported, the bytes
        carry no tables, or no usable key/value pair is found.
    """
    if not data:
        return None
    suffix = _normalize_suffix(file_type)
    extractor = _EXTRACTORS.get(suffix)
    if extractor is None:
        return None
    tables = extractor(io.BytesIO(data))
    lines: List[str] = []
    for table in tables:
        lines.extend(reconstruct_table_lines(table))
    return _lines_to_text(lines)


def is_table_reconstruction_type(file_type: str) -> bool:
    """Return whether a bare file type token is a supported document type."""
    return _normalize_suffix(file_type) in _SUPPORTED_SUFFIXES


def iter_reconstructed_lines(tables: Iterable[Sequence[Sequence[object]]]) -> List[str]:
    """Reconstruct many tables into a flat list of ``key: value`` lines."""
    lines: List[str] = []
    for table in tables:
        lines.extend(reconstruct_table_lines(table))
    return lines


__all__ = [
    "CREDENTIAL_HEADER_KEYWORDS",
    "DocumentSource",
    "Table",
    "document_has_tables",
    "extract_document_tables",
    "is_table_reconstruction_candidate",
    "is_table_reconstruction_type",
    "iter_reconstructed_lines",
    "reconstruct_document_table_text",
    "reconstruct_document_table_text_from_bytes",
    "reconstruct_table_lines",
]
