"""
report_generator.py

Renders templates/report_template.html using Jinja2 and converts to PDF
using either WeasyPrint (default) or wkhtmltopdf (pdfkit).

Features:
- Embeds a label-probability PNG chart (base64).
- Accepts scan["raw_outputs"] or attach_files list (paths or pre-shaped dicts).
- Automatically embeds images (base64) and text outputs (preformatted).
- Thread-safe to call from GUI background threads.

Usage:
    from report_generator import generate_pdf_from_scan
    generate_pdf_from_scan(scan_dict, "./scan-report.pdf", method="weasyprint", attach_files=[...])
"""

import os
import io
import base64
import webbrowser
import tempfile
import mimetypes
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Matplotlib for chart creation
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Optional PDF engines
try:
    import pdfkit
except Exception:
    pdfkit = None

try:
    from weasyprint import HTML
except Exception:
    HTML = None

# Template environment
THIS_DIR = os.path.dirname(__file__)
TEMPLATE_DIR = os.path.join(THIS_DIR, "templates")
env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"])
)

TEMPLATE_NAME = "report_template.html"

# ---------- Helpers ----------

def _make_label_prob_chart(label_probs: dict, width=800, height=240):
    """
    Returns PNG bytes of a horizontal bar chart for label_probs.
    label_probs: dict of {label: float (0-1)}
    """
    labels = list(label_probs.keys())
    vals = [float(label_probs[k]) for k in labels]

    fig, ax = plt.subplots(figsize=(width/100, height/100))
    y_pos = range(len(labels))
    ax.barh(y_pos, vals)
    ax.set_yticks(y_pos)
    ax.set_yticklabels([str(l) for l in labels], fontsize=8)
    ax.set_xlim(0, 1)
    ax.invert_yaxis()
    ax.set_xlabel("Probability")
    ax.set_title("Predicted label probabilities")
    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=100, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.read()

def prepare_raw_output_item(path_or_dict):
    """
    Accept either a dict already shaped for template, or a filesystem path string.
    Returns normalized dict with keys:
      - name, label (optional), type ('text'|'image'|'link'), content (text or base64), img_format, source, href
    """
    if isinstance(path_or_dict, dict):
        # Assume already shaped correctly; shallow copy to avoid mutation
        item = dict(path_or_dict)
        return item

    path = str(path_or_dict)
    name = os.path.basename(path)
    item = {"name": name, "source": path}

    if not os.path.exists(path):
        # Non-existing path -> produce link
        item.update({"type": "link", "href": path})
        return item

    # Guess MIME type
    mime, _ = mimetypes.guess_type(path)
    if mime and mime.startswith("image/"):
        fmt = mime.split("/")[1]  # 'png', 'jpeg', etc.
        with open(path, "rb") as fh:
            b = fh.read()
        b64 = base64.b64encode(b).decode("ascii")
        item.update({"type": "image", "content": b64, "img_format": fmt})
        return item

    # Otherwise try to read as text
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            txt = fh.read()
        # Optionally truncate very large files (keep full file as link)
        MAX_CHARS = 200_000
        if len(txt) > MAX_CHARS:
            txt_preview = txt[:MAX_CHARS] + "\n\n[TRUNCATED]\nFull file available at: " + path
            item.update({"type": "text", "content": txt_preview})
            item["href"] = path
        else:
            item.update({"type": "text", "content": txt})
        return item
    except Exception:
        item.update({"type": "link", "href": path})
        return item

# ---------- Main generator ----------

def generate_pdf_from_scan(scan: dict,
                           out_path: str,
                           method: str = "weasyprint",
                           wkhtmltopdf_path: str = None,
                           model_name: str = None,
                           note: str = None,
                           attach_files: list = None):
    """
    Generate a PDF report from `scan` dict.

    Parameters:
      - scan: dict with keys expected by template (target, date, cves, features, label_probs, report_id, raw_outputs optional)
      - out_path: output PDF path
      - method: "weasyprint" (default) or "wkhtmltopdf"
      - wkhtmltopdf_path: path to wkhtmltopdf binary if using wkhtmltopdf and not in PATH
      - model_name, note: optional strings passed to template
      - attach_files: optional list of file paths or dicts to attach inline (adds to scan['raw_outputs'])
    Returns:
      - the out_path on success, raises on failure
    """
    template = env.get_template(TEMPLATE_NAME)

    # Prepare chart image (base64) if label_probs present
    chart_b64 = None
    if scan.get("label_probs"):
        try:
            png = _make_label_prob_chart(scan["label_probs"])
            chart_b64 = base64.b64encode(png).decode("ascii")
        except Exception:
            chart_b64 = None

    # Process attachments
    raw_list = []
    if scan.get("raw_outputs"):
        for item in scan.get("raw_outputs"):
            raw_list.append(prepare_raw_output_item(item))

    if attach_files:
        for p in attach_files:
            raw_list.append(prepare_raw_output_item(p))

    # Deduplicate attachments by source/href/name
    seen = set()
    deduped = []
    for it in raw_list:
        key = (it.get("source") or it.get("href") or it.get("name"))
        if not key:
            continue
        if key in seen:
            continue
        seen.add(key)
        deduped.append(it)

    # Prepare scan copy for template
    scan_for_template = dict(scan) if isinstance(scan, dict) else {"scan": scan}
    if deduped:
        scan_for_template["raw_outputs"] = deduped

    export_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Render HTML
    html = template.render(
        scan=scan_for_template,
        chart_data=chart_b64,
        export_time=export_time,
        model_name=model_name,
        note=note
    )

    # Ensure out dir exists
    out_dir = os.path.dirname(out_path) or "."
    os.makedirs(out_dir, exist_ok=True)

    method = (method or "weasyprint").lower()
    if method in ("wkhtmltopdf", "pdfkit"):
        if pdfkit is None:
            raise RuntimeError("pdfkit not installed. pip install pdfkit")
        config = None
        if wkhtmltopdf_path:
            config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
        options = {
            "page-size": "A4",
            "margin-top": "18mm",
            "margin-bottom": "18mm",
            "margin-left": "16mm",
            "margin-right": "16mm",
            "encoding": "UTF-8",
            "enable-local-file-access": None,
        }
        pdfkit.from_string(html, out_path, options=options, configuration=config)
        return out_path

    elif method in ("weasyprint",):
        if HTML is None:
            raise RuntimeError("WeasyPrint not installed. pip install weasyprint")
        HTML(string=html).write_pdf(out_path)
        return out_path

    else:
        raise ValueError("Unknown method: choose 'weasyprint' or 'wkhtmltopdf'.")

def generate_html_from_scan(scan: dict,
                            out_path: str = None,
                            model_name: str = None,
                            note: str = None,
                            attach_files: list = None,
                            embed_chart: bool = True) -> str:
    """
    Render the report_template.html with `scan` and write an HTML file.
    If out_path is None, creates a temporary file and returns its path.
    Does NOT convert to PDF.
    """
    # reuse prepare_raw_output_item and chart generation
    chart_b64 = None
    if embed_chart and scan.get("label_probs"):
        try:
            png = _make_label_prob_chart(scan["label_probs"])
            chart_b64 = base64.b64encode(png).decode("ascii")
        except Exception:
            chart_b64 = None

    # Process attachments like generate_pdf_from_scan does
    raw_list = []
    if scan.get("raw_outputs"):
        for item in scan.get("raw_outputs"):
            raw_list.append(prepare_raw_output_item(item))
    if attach_files:
        for p in attach_files:
            raw_list.append(prepare_raw_output_item(p))
    # dedupe
    seen = set()
    deduped = []
    for it in raw_list:
        key = (it.get("source") or it.get("href") or it.get("name"))
        if not key:
            continue
        if key in seen:
            continue
        seen.add(key)
        deduped.append(it)

    scan_for_template = dict(scan) if isinstance(scan, dict) else {"scan": scan}
    if deduped:
        scan_for_template["raw_outputs"] = deduped

    export_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    template = env.get_template(TEMPLATE_NAME)
    html = template.render(
        scan=scan_for_template,
        chart_data=chart_b64,
        export_time=export_time,
        model_name=model_name,
        note=note
    )

    # write out_path or temp file
    if not out_path:
        fd, tmp_path = tempfile.mkstemp(prefix="scan_report_", suffix=".html")
        os.close(fd)
        out_path = tmp_path
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return out_path

def open_html_in_browser(path: str):
    """Convenience: open a local file in the default web browser."""
    if not path:
        return
    # make absolute file:// URI and open
    fileurl = "file://" + os.path.abspath(path)
    webbrowser.open(fileurl)
    
# ---------- Example / quick test ----------

def example_scan():
    return {
        "target": "example.com",
        "date": "2025-11-09 22:00:00",
        "tools": ["nmap", "nikto"],
        "prediction": "Likely vulnerable: web-exploit chain detected (medium confidence)",
        "cves": [
            {"cve_id": "CVE-2023-12345", "cvss_v3": 7.8, "summary": "Example vulnerable service", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
            {"cve_id": "CVE-2024-99999", "cvss_v3": 5.3, "summary": "Minor issues found"}
        ],
        "features": {
            "total_open_ports": 4,
            "port_80_open": True,
            "port_443_open": True,
            "nikto_high_risk_findings": 1,
        },
        "label_probs": {"vuln_web": 0.72, "vuln_rce": 0.10, "benign": 0.18},
        "report_id": "RPT-001"
    }

if __name__ == "__main__":
    s = example_scan()
    out = os.path.join(os.getcwd(), "scan-report.pdf")
    print("Generating:", out)
    # method: "weasyprint" or "wkhtmltopdf"
    generate_pdf_from_scan(s, out, method="weasyprint")
    print("Done.")
