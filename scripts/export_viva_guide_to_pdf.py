import os
import shutil
import subprocess
import tempfile
import markdown

SOURCE_MD = r"C:\Users\Angad\.gemini\antigravity-cli\brain\baa57c99-b090-44dc-b721-59ec945a89e5\VIVA_PRESENTATION_AND_STUDY_GUIDE.md"
TARGET_PDF1 = r"C:\Users\Angad\.gemini\antigravity-cli\brain\baa57c99-b090-44dc-b721-59ec945a89e5\VIVA_PRESENTATION_AND_STUDY_GUIDE.pdf"
TARGET_PDF2 = r"C:\Users\Angad\AACIP\docs\VIVA_PRESENTATION_AND_STUDY_GUIDE.pdf"

CSS = """
@page {
    size: A4;
    margin: 1.6cm 1.6cm 1.8cm 1.6cm;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.55;
    color: #1e293b;
    background: #ffffff;
    padding: 0;
    margin: 0;
}

h1 {
    font-size: 18pt;
    color: #0f172a;
    border-bottom: 2.5px solid #2563eb;
    padding-bottom: 6px;
    margin-top: 0;
    margin-bottom: 12px;
    page-break-after: avoid;
}

h2 {
    font-size: 13pt;
    color: #1e3a8a;
    border-bottom: 1px solid #cbd5e1;
    padding-bottom: 4px;
    margin-top: 20px;
    margin-bottom: 10px;
    page-break-after: avoid;
}

h3 {
    font-size: 11pt;
    color: #1d4ed8;
    margin-top: 14px;
    margin-bottom: 6px;
    page-break-after: avoid;
}

p, ul, ol {
    margin-top: 4px;
    margin-bottom: 8px;
}

strong {
    color: #0f172a;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
    font-size: 8.8pt;
    page-break-inside: avoid;
}

th, td {
    border: 1px solid #cbd5e1;
    padding: 7px 9px;
    text-align: left;
    vertical-align: top;
}

th {
    background-color: #f1f5f9;
    color: #0f172a;
    font-weight: 600;
}

tr:nth-child(even) td {
    background-color: #f8fafc;
}

blockquote {
    margin: 6px 0 10px 0;
    padding: 7px 12px;
    background-color: #f8fafc;
    border-left: 3.5px solid #2563eb;
    color: #334155;
    font-style: italic;
    page-break-inside: avoid;
}

blockquote p {
    margin: 0;
}

code {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8.8pt;
    background-color: #f1f5f9;
    padding: 2px 4px;
    border-radius: 3px;
    color: #0284c7;
}

a {
    color: #2563eb;
    text-decoration: none;
}

hr {
    border: 0;
    height: 1px;
    background: #e2e8f0;
    margin: 16px 0;
}

ul {
    padding-left: 20px;
}

li {
    margin-bottom: 4px;
}
"""

def main():
    if not os.path.exists(SOURCE_MD):
        print(f"Error: Source file {SOURCE_MD} not found.")
        return

    with open(SOURCE_MD, "r", encoding="utf-8") as f:
        md_content = f.read()

    html_content = markdown.markdown(md_content, extensions=["extra", "tables", "nl2br"])

    full_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AACIP - Viva Presentation Script & Technical Defense Guide</title>
<style>
{CSS}
</style>
</head>
<body>
{html_content}
</body>
</html>"""

    with tempfile.NamedTemporaryFile("w", suffix=".html", encoding="utf-8", delete=False) as tf:
        tf.write(full_html)
        temp_html_path = tf.name

    browser = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    if not os.path.exists(browser):
        browser = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

    cmd = [
        browser,
        "--headless",
        "--disable-gpu",
        "--run-all-compositor-stages-before-draw",
        f"--print-to-pdf={TARGET_PDF1}",
        "--no-pdf-header-footer",
        temp_html_path
    ]

    print(f"Converting markdown to PDF via {browser}...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if os.path.exists(TARGET_PDF1) and os.path.getsize(TARGET_PDF1) > 0:
        size_kb = os.path.getsize(TARGET_PDF1) / 1024
        print(f"Generated PDF successfully: {TARGET_PDF1} ({size_kb:.1f} KB)")
        
        # Ensure destination directory exists and copy
        os.makedirs(os.path.dirname(TARGET_PDF2), exist_ok=True)
        shutil.copy2(TARGET_PDF1, TARGET_PDF2)
        print(f"Copied to project docs: {TARGET_PDF2}")
    else:
        print("Failed to generate PDF.")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)

    if os.path.exists(temp_html_path):
        os.remove(temp_html_path)

if __name__ == "__main__":
    main()
