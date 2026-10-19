import os
import tempfile
from datetime import datetime, timezone
from fpdf import FPDF


def generate_forensic_report_pdf(scan_data: dict) -> str:
    """
    Generate a forensic PDF report and return the path to a temporary file.
    The caller is responsible for serving the file; FastAPI's FileResponse
    will delete it after the response is sent when background=None is set.
    Using a unique tempfile per call (F-25) prevents concurrent requests from
    overwriting each other's PDF.
    """
    d = scan_data
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(108, 99, 255)
    pdf.cell(0, 12, "PHISHNOT AI", ln=True, align="C")
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(139, 143, 163)
    pdf.cell(0, 8, "Neural Forensic Analysis Report", ln=True, align="C")
    pdf.cell(0, 6,
             f"Scan ID: {d.get('scan_id', 'N/A')} | "
             f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
             ln=True, align="C")
    pdf.ln(6)

    pred       = d.get('prediction', 'unknown').upper()
    confidence = d.get('confidence', 0) * 100
    reasoning  = d.get('reasoning') or {}
    risk_score = reasoning.get('risk_score', 0)
    risk_level = reasoning.get('risk_level', 'N/A')

    if pred == "PHISHING":
        r, g, b = 239, 68, 68
    elif pred == "SPAM":
        r, g, b = 245, 158, 11
    else:
        r, g, b = 34, 197, 94

    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 14, f"VERDICT: {pred}", ln=True, align="C", fill=True)
    pdf.ln(4)

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Confidence: {confidence:.1f}%", ln=True)
    pdf.cell(0, 7, f"Risk Score: {risk_score}/100 ({risk_level})", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Model Consensus", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for model, info in d.get('model_predictions', {}).items():
        pdf.cell(0, 6,
                 f"{model.replace('_', ' ').title()}: "
                 f"{info['prediction'].upper()} (conf: {info['confidence']:.1%})",
                 ln=True)
    pdf.ln(4)

    if reasoning.get('risk_story'):
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Attack Analysis", ln=True)
        pdf.set_font("Helvetica", "", 10)
        story = reasoning['risk_story'].replace('**', '').replace(' | Risk Score:', '')
        pdf.multi_cell(0, 6, story)
        pdf.ln(3)

    practices = reasoning.get('best_practices', [])
    if practices:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Recommended Actions", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for i, p in enumerate(practices, 1):
            pdf.cell(0, 6, f"{i}. {p}", ln=True)
    pdf.ln(8)

    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(139, 143, 163)
    pdf.cell(0, 6, "This is an automated security analysis.", ln=True, align="C")

    # F-25: write to a unique temp file; never overwrite a concurrent request's PDF
    fd, path = tempfile.mkstemp(suffix=".pdf", prefix="phishnot_report_")
    os.close(fd)
    pdf.output(path)
    return path
