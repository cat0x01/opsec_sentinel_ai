from __future__ import annotations

from typing import Optional


def export_pdf(html: str, output_path: str) -> Optional[str]:
    try:
        from weasyprint import HTML  # type: ignore
    except Exception:
        return None

    HTML(string=html).write_pdf(output_path)
    return output_path
