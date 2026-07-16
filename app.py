import os
import uuid
import zipfile
import pandas as pd
import PyPDF2
import pytesseract

pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "bmp", "tiff", "tif"}
from flask import Flask, render_template, request, send_file, redirect, session, after_this_request
from werkzeug.utils import secure_filename
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from dotenv import load_dotenv
load_dotenv()
from gemini_service import ask_gemini
from flask import jsonify

from anonymizer import (
    SECTOR_RULES, detect_sector, detect_sensitive, anonymize_text,
    anonymize_dataframe, risk_dashboard, k_anonymity_preview
)

try:
    from docx import Document
except Exception:
    Document = None

try:
    from PIL import Image, ImageOps, ImageFilter
    import pytesseract
except Exception:
    Image = None
    ImageOps = None
    ImageFilter = None
    pytesseract = None

# Windows-friendly Tesseract setup.
# pytesseract is only the Python wrapper; the Tesseract OCR engine must also be installed.
# This auto-detects common Windows install paths so OCR works without editing code.
def _configure_tesseract():
    if pytesseract is None:
        return
    candidates = [
        os.environ.get("TESSERACT_CMD"),
        r"C:\\Program Files\\Tesseract-OCR\\tesseract.exe",
        r"C:\\Program Files (x86)\\Tesseract-OCR\\tesseract.exe",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            pytesseract.pytesseract.tesseract_cmd = candidate
            return

_configure_tesseract()


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24))
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "output_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"txt", "csv", "xlsx", "pdf", "docx", "zip"} | IMAGE_EXTENSIONS
OUTPUT_FORMAT_LABELS = {
    "txt": "Plain Text (.txt)",
    "csv": "CSV (.csv)",
    "xlsx": "Excel (.xlsx)",
    "pdf": "PDF (.pdf)",
}

# Files we can read text/tables out of when they appear inside a .zip upload.
READABLE_INNER = {"txt", "csv", "xlsx", "pdf", "docx"} | IMAGE_EXTENSIONS
# Formats _write_output can actually produce. Anything else falls back to .txt.
WRITABLE_EXTENSIONS = {"txt", "csv", "xlsx", "pdf"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def _preprocess_image_for_ocr(filepath):
    """Make screenshots/photos easier for OCR to read."""
    image = Image.open(filepath).convert("RGB")

    # Upscale small screenshots/photos. OCR is more accurate on larger text.
    w, h = image.size
    if max(w, h) < 1800:
        image = image.resize((w * 2, h * 2))

    # Convert to grayscale, improve contrast, then sharpen slightly.
    gray = ImageOps.grayscale(image)
    gray = ImageOps.autocontrast(gray)
    gray = gray.filter(ImageFilter.SHARPEN)
    return gray

def _read_image_with_ocr(filepath):
    """Extract text from image/photo files using OCR.

    Requires:
    1. Pillow + pytesseract from requirements.txt
    2. Tesseract OCR engine installed on the laptop

    If OCR fails, return a clear message instead of silently giving Detected: 0.
    """
    if Image is None or pytesseract is None:
        return (
            "[OCR ERROR: Pillow/pytesseract is not installed. Run: pip install -r requirements.txt]",
            None,
        )

    try:
        image = _preprocess_image_for_ocr(filepath)
        config = "--oem 3 --psm 6"
        text = pytesseract.image_to_string(image, config=config)

        # If psm 6 is too strict, retry with automatic page segmentation.
        if not text.strip():
            text = pytesseract.image_to_string(image, config="--oem 3 --psm 11")

        if not text.strip():
            return (
                "[OCR WARNING: Image uploaded successfully, but no readable text was found. "
                "Use a clearer image or screenshot with typed text.]",
                None,
            )

        return text, None

    except Exception as e:
        return (
            "[OCR ERROR: Tesseract OCR is not installed or not found. "
            "Install Tesseract OCR for Windows, or set TESSERACT_CMD to the tesseract.exe path. "
            f"Details: {e}]",
            None,
        )

def _read_single_file_as_text(filepath, ext):
    if ext == "txt":
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(), None
    if ext == "csv":
        try:
            df = pd.read_csv(filepath)

            if df.empty:
                return "[Empty CSV File]", None

            return df.to_string(index=False), df

        except pd.errors.EmptyDataError:
            return "[Empty CSV File]", None

        except Exception as e:
            return (f"[CSV ERROR: {e}]", None)

    if ext == "xlsx":
        try:
            df = pd.read_excel(filepath)

            if df.empty:
                return "[Empty Excel File]", None

            return df.to_string(index=False), df

        except Exception as e:
            return (f"[Excel ERROR: {e}]", None)

    if ext == "pdf":
        text = ""
        with open(filepath, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text += extracted + "\n"
        return text, None

    if ext == "docx":
        if Document is None:
            return "[DOCX support requires python-docx. Install requirements.txt]", None
        doc = Document(filepath)
        return "\n".join([p.text for p in doc.paragraphs]), None
    if ext in IMAGE_EXTENSIONS:
        return _read_image_with_ocr(filepath)
    return "", None


# ---------------------------------------------------------------------------
# Multi-file handling
# ---------------------------------------------------------------------------
# One upload can expand into several "documents":
#   - a normal file  -> one document
#   - a .zip folder  -> one document per readable file inside it
#   - an image       -> one document whose text comes from OCR
# Treating each file as its own document lets us detect sectors across the whole
# batch, yet still hand every file back in the SAME shape it was uploaded in.

def _expand_zip(filepath):
    """Return one document per readable file stored inside a .zip upload."""
    docs = []
    with zipfile.ZipFile(filepath, "r") as z:
        for name in z.namelist():
            if name.endswith("/"):
                continue
            inner_ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if inner_ext not in READABLE_INNER:
                continue
            temp_name = f"{uuid.uuid4().hex}_{secure_filename(os.path.basename(name))}"
            temp_path = os.path.join(UPLOAD_FOLDER, temp_name)
            with open(temp_path, "wb") as f:
                f.write(z.read(name))
            try:
                text, df = _read_single_file_as_text(temp_path, inner_ext)
            except Exception as e:
                text, df = f"[ERROR reading {name}: {e}]", None
            finally:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            docs.append({"name": os.path.basename(name), "ext": inner_ext, "text": text, "df": df})
    return docs


def _collect_documents(files):
    """Read every saved upload from disk into a flat list of documents.
    Zip uploads are expanded so each inner file becomes its own document."""
    documents = []
    for f in files:
        filepath = os.path.join(UPLOAD_FOLDER, f["filename"])
        if not os.path.exists(filepath):
            continue
        ext = f["ext"]
        display = f.get("original", f["filename"])
        if ext == "zip":
            documents.extend(_expand_zip(filepath))
        else:
            try:
                text, df = _read_single_file_as_text(filepath, ext)
            except Exception as e:
                text, df = f"[ERROR reading {display}: {e}]", None
            documents.append({"name": display, "ext": ext, "text": text, "df": df})
    return documents


def _aggregate_detected(documents, sector):
    """Sum the sensitive-item counts across every document."""
    totals = {}
    for d in documents:
        for key, val in detect_sensitive(d["text"], sector, d["df"]).items():
            totals[key] = totals.get(key, 0) + int(val)
    return totals


def _combined_text_and_columns(documents):
    """Concatenate all document text + gather all column names for detection."""
    text_parts = []
    columns = []
    for d in documents:
        text_parts.append(d["text"] or "")
        if d["df"] is not None:
            columns.extend(list(d["df"].columns))
    return "\n\n".join(text_parts), columns


def _combined_dataframe(documents):
    """Merge every tabular document into one frame (used for k-anonymity)."""
    frames = [d["df"] for d in documents if d["df"] is not None]
    if not frames:
        return None
    if len(frames) == 1:
        return frames[0]
    try:
        return pd.concat(frames, ignore_index=True, sort=False)
    except Exception:
        return frames[0]


def _write_output(anonymized, df_original, input_ext, output_ext, output_path, selected_items):
    """
    Save the anonymised data into the requested format.
    Supports: TXT, CSV, XLSX, PDF. Anything else is written as plain text so we
    never crash on formats we cannot rebuild (zip, docx, images, ...).
    """
    if output_ext not in WRITABLE_EXTENSIONS:
        output_ext = "txt"

    # ---------------- TXT ----------------
    if output_ext == "txt":
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(anonymized)
        return

    # ---------------- CSV ----------------
    elif output_ext == "csv":

        # If original file was a dataframe
        if df_original is not None:

            df = anonymize_dataframe(df_original, selected_items)
            df.to_csv(output_path, index=False)

        else:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(anonymized)

        return

    # ---------------- Excel ----------------
    elif output_ext == "xlsx":

        if df_original is not None:

            df = anonymize_dataframe(df_original, selected_items)
            df.to_excel(output_path, index=False)

        else:

            df = pd.DataFrame({"Anonymized Data":[anonymized]})
            df.to_excel(output_path, index=False)

        return

    # ---------------- PDF ----------------
    elif output_ext == "pdf":

        doc = SimpleDocTemplate(output_path)

        styles = getSampleStyleSheet()

        story = []

        story.append(Paragraph("<b>Secure Data Anonymizer Report</b>", styles["Heading1"]))
        story.append(Paragraph("<br/>", styles["Normal"]))

        # dataframe
        if df_original is not None:

            df = anonymize_dataframe(df_original, selected_items)

            text = df.to_string(index=False)

        else:

            text = anonymized

        for line in text.split("\n"):
            line = line.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            story.append(Paragraph(line, styles["BodyText"]))
        doc.build(story)
        return

@app.route("/")
def upload_page():
    return render_template("upload.html", sectors=SECTOR_RULES)

def detect_all_sectors(documents):
    """
    Detect sectors across all uploaded documents and rank them by total score.
    """

    sector_scores = {
        "banking": 0,
        "healthcare": 0,
        "it": 0,
    }

    matched_keywords = {
        "banking": [],
        "healthcare": [],
        "it": [],
    }

    for doc in documents:

        columns = list(doc["df"].columns) if doc["df"] is not None else []

        _, scores, keywords = detect_sector(
            doc["text"],
            columns
        )

        for sector, score in scores.items():
            sector_scores[sector] += score

        for sector, words in keywords.items():
            matched_keywords[sector].extend(words)

    ranked = sorted(
        sector_scores,
        key=sector_scores.get,
        reverse=True
    )

    detected = [
        s for s in ranked
        if sector_scores[s] > 0
    ]

    if not detected:
        detected = ["banking"]

    return detected, sector_scores, matched_keywords

@app.route("/upload", methods=["POST"])
def upload():

    files = request.files.getlist("file")
    manual_sector = request.form.get("sector", "auto")

    if not files or files[0].filename == "":
        return render_template(
            "upload.html",
            error="No files selected.",
            sectors=SECTOR_RULES
        )

    # -----------------------
    # Save every uploaded file to disk
    # -----------------------
    uploaded_files = []
    for file in files:

        if file.filename == "" or not allowed_file(file.filename):
            continue

        filename = secure_filename(file.filename)
        ext = filename.rsplit(".", 1)[1].lower()
        unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
        filepath = os.path.join(UPLOAD_FOLDER, unique_name)
        file.save(filepath)

        print("Uploaded:", filename, "->", ext, os.path.getsize(filepath), "bytes")

        uploaded_files.append({
            "filename": unique_name,
            "original": filename,
            "ext": ext,
        })

    if not uploaded_files:
        return render_template(
            "upload.html",
            error="No valid files uploaded.",
            sectors=SECTOR_RULES
        )

    # -----------------------
    # Read + expand everything (zips become many documents) so sector
    # detection and risk counting see the entire batch at once.
    # -----------------------
    documents = _collect_documents(uploaded_files)
    if not documents:
        return render_template(
            "upload.html",
            error="Uploaded files could not be read.",
            sectors=SECTOR_RULES
        )

    combined_text, columns = _combined_text_and_columns(documents)

    combined_df = _combined_dataframe(documents)

    detected_sectors, sector_scores, matched_keywords = detect_all_sectors(
        documents
    )

    print("=" * 50)
    print("Detected Sectors:", detected_sectors)
    print("Sector Scores:", sector_scores)
    print("=" * 50)
    
    if manual_sector == "auto":
        sectors_to_use = detected_sectors
    else:
        sectors_to_use = [manual_sector]

    detected = {}

    for sector in sectors_to_use:
        result = detect_sensitive(
            text=combined_text,
            sectors=sector,
            df=combined_df
        )

        for k, v in result.items():
            detected[k] = detected.get(k, 0) + int(v)

    # OCR status summary across any image documents (including images in a zip).
    ocr_message = ""
    ocr_preview = ""
    for d in documents:
        if d["ext"] in IMAGE_EXTENSIONS:
            if (d["text"] or "").startswith("[OCR"):
                ocr_message += d["text"] + "\n"
            else:
                ocr_message += f"{d['name']}: OCR completed successfully.\n"
                if not ocr_preview:
                    ocr_preview = (d["text"] or "")[:800]

    session["files"] = uploaded_files
    session["sectors"] = sectors_to_use
    best_sector = max(sector_scores,key=sector_scores.get)
    session["suggested_sector"] = best_sector
    sector_scores = {k: int(v) for k, v in sector_scores.items()}
    session["sector_scores"] = sector_scores
    session["matched_keywords"] = matched_keywords
    detected = {k: int(v) for k, v in detected.items()}
    session["detected"] = detected
    session["ocr_message"] = ocr_message
    session["ocr_preview"] = ocr_preview
    chat_context = f"""
    Detected Sectors:
    {', '.join(detected_sectors)}

    Detected Personal Data:
    {detected}

    Sector Scores:
    {sector_scores}

    OCR Status:
    {ocr_message}

    Document Content:
    {combined_text[:12000]}
    """
    session["chat_context"] = chat_context
    
    return redirect("/select")


@app.route("/select")
def select():
    if not session.get("files"):
        return redirect("/")

    detected_sectors = session.get("sectors",[session.get("suggested_sector", "banking")])

    # "Same as uploaded" keeps every file in its own format; the rest let the
    # user force one format for all outputs.
    output_formats = {"original": "Same as uploaded file(s)"}
    output_formats.update(OUTPUT_FORMAT_LABELS)

    combined_rules = {
    "label": "Detected Sectors",
    "description": "All anonymization techniques from detected sectors will be applied automatically.",
    "items": {}
    }

    for s in session.get("sectors", []):
        combined_rules["items"].update(SECTOR_RULES[s]["items"])

    return render_template(
        "options.html",
        sectors=SECTOR_RULES,
        detected_sectors=detected_sectors,
        sector_rules=combined_rules,
        suggested_sectors=detected_sectors,
        sector_scores=session.get("sector_scores", {}),
        matched_keywords=session.get("matched_keywords", {}),
        detected=session.get("detected", {}),
        ocr_message=session.get("ocr_message", ""),
        ocr_preview=session.get("ocr_preview", ""),
        output_formats=output_formats,
        input_ext="original",
    )


@app.route("/change-sector", methods=["POST"])
def change_sector():
    files = session.get("files", [])
    if not files:
        return redirect("/")

    sector = request.form.get("sector", session.get("sector", "banking"))
    if sector not in SECTOR_RULES:
        sector = "banking"

    documents = _collect_documents(files)
    session["sector"] = sector
    session["detected"] = _aggregate_detected(documents, sector)

    return redirect("/select")


@app.route("/process", methods=["POST"])
def process():
    if "consent" not in request.form:
        return redirect("/select")

    files = session.get("files", [])
    if not files:
        return redirect("/")

    documents = _collect_documents(files)
    if not documents:
        session.clear()
        return render_template(
            "upload.html",
            error="Uploaded files were not found. Please upload again.",
            sectors=SECTOR_RULES
        )

    sectors = session.get("sectors",[session.get("suggested_sector", "banking")])
    selected_items = request.form.getlist("protect")
    output_choice = request.form.get("output_format", "original").lower()

    before_total = {}
    after_total = {}
    outputs = []            # (output_name, output_path) per file
    preview_original = ""
    preview_anonymized = ""

    # -----------------------
    # Anonymise every document independently
    # -----------------------
    for idx, d in enumerate(documents, start=1):
        text = d["text"] or ""
        df_original = d["df"]
        ext = d["ext"]

        before_counts = {}

        before_counts = detect_sensitive(
            text,
            sectors,
            df_original
        )

        if df_original is not None and ext in {"csv", "xlsx"}:
            df_anon = anonymize_dataframe(df_original, selected_items)
            anonymized = df_anon.to_string(index=False)
            after_counts = detect_sensitive(
                anonymized,
                sectors,
                df_anon
            )
        else:
            anonymized, _ = anonymize_text(text, selected_items)
            after_counts = detect_sensitive(
                anonymized,
                sectors,
                None
            )

        for k, v in before_counts.items():
            before_total[k] = before_total.get(k, 0) + int(v)
        for k, v in after_counts.items():
            after_total[k] = after_total.get(k, 0) + int(v)

        # Keep each file's own format unless the user forced one. Formats we
        # cannot rebuild (zip/docx/image) fall back to .txt inside _write_output.
        out_ext = ext if output_choice == "original" else output_choice
        if out_ext not in WRITABLE_EXTENSIONS:
            out_ext = "txt"

        base = os.path.splitext(os.path.basename(d["name"]))[0]
        output_name = f"anonymized_{idx:02d}_{secure_filename(base)}.{out_ext}"
        output_path = os.path.join(OUTPUT_FOLDER, output_name)
        _write_output(anonymized, df_original, ext, out_ext, output_path, selected_items)
        outputs.append((output_name, output_path))

        preview_original += f"\n\n===== {d['name']} =====\n\n" + text[:1000]
        preview_anonymized += f"\n\n===== {d['name']} =====\n\n" + anonymized[:1000]

    # -----------------------
    # Bundle results: one file -> hand it back directly; many -> zip them.
    # -----------------------
    if len(outputs) == 1:
        output_file = outputs[0][0]
    else:
        output_file = "anonymized_files.zip"
        zip_path = os.path.join(OUTPUT_FOLDER, output_file)
        with zipfile.ZipFile(zip_path, "w") as zipf:
            for name, path in outputs:
                zipf.write(path, arcname=name)
        for name, path in outputs:
            try:
                os.remove(path)
            except OSError:
                pass

    combined_df = _combined_dataframe(documents)
    dashboard = risk_dashboard(
        before_total,
        after_total,
        sectors,
        selected_items
    )

    kanon = k_anonymity_preview(combined_df)
    total_changes = sum(
        max(0, int(before_total.get(k, 0)) - int(after_total.get(k, 0)))
        for k in before_total
    )
    selected_labels = []

    for sector in sectors:

        for k in selected_items:

            if k in SECTOR_RULES[sector]["items"]:

                label = SECTOR_RULES[sector]["items"][k]["label"]

                if label not in selected_labels:
                    selected_labels.append(label)

    orig_preview_path = os.path.join(OUTPUT_FOLDER, "preview_original.txt")
    anon_preview_path = os.path.join(OUTPUT_FOLDER, "preview_anonymized.txt")
    with open(orig_preview_path, "w", encoding="utf-8") as f:
        f.write(preview_original)
    with open(anon_preview_path, "w", encoding="utf-8") as f:
        f.write(preview_anonymized)
    
    session["suggested_sectors"] = sectors
    session["output"] = output_file
    session["orig_preview"] = orig_preview_path
    session["anon_preview"] = anon_preview_path
    session["techniques"] = selected_labels
    session["dashboard"] = dashboard
    session["kanon"] = kanon
    session["total_changes"] = total_changes
    return redirect("/preview")

@app.route("/preview")
def preview():

    original = ""
    anonymized = ""

    if session.get("orig_preview") and os.path.exists(session["orig_preview"]):
        with open(session["orig_preview"], "r", encoding="utf-8") as f:
            original = f.read()

    if session.get("anon_preview") and os.path.exists(session["anon_preview"]):
        with open(session["anon_preview"], "r", encoding="utf-8") as f:
            anonymized = f.read()

    sectors = session.get("suggested_sectors", ["banking"])
    sector = sectors[0] 

    combined_rules = {
    "label": "Detected Sectors",
    "description": "All anonymization techniques from detected sectors.",
    "items": {}
    }

    for s in sectors:
        combined_rules["items"].update(SECTOR_RULES[s]["items"])

    return render_template(
        "preview.html",
        original=original,
        anonymized=anonymized,
        sectors=SECTOR_RULES,
        suggested_sectors=sectors,
        sector=sector,
        sector_rules=combined_rules,
        techniques=session.get("techniques", []),
        dashboard=session.get("dashboard", {}),
        kanon=session.get("kanon"),
        total_changes=session.get("total_changes", 0),
    )


@app.route("/getfile")
def getfile():
    file = session.get("output")
    if not file:
        return redirect("/")

    path = os.path.join(OUTPUT_FOLDER, file)

    @after_this_request
    def cleanup(response):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass
        return response

    return send_file(path, as_attachment=True)

@app.route("/reset")
def reset():

    for f in session.get("files", []):

        path = os.path.join(
            UPLOAD_FOLDER,
            f["filename"]
        )

        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

    session.clear()

    return redirect("/")

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()

    message = data.get("message", "").lower().strip()

    context = session.get("chat_context", "")

    # ===========================
    # Built-in system responses
    # ===========================

    if any(x in message for x in [
        "multiple files",
        "multiple file",
        "upload multiple",
        "more than one file",
        "batch upload"
    ]):

        return jsonify({
            "reply": """
Yes. The **Secure Data Anonymizer** supports uploading **multiple files** in a single session.

**Benefits**

- Upload several documents at once.
- Save time by processing files together.
- Apply consistent anonymization across all uploaded files.
- Easily review each document before downloading the anonymized versions.

**Supported File Types**

- PDF (.pdf)
- Word (.docx)
- Excel (.xlsx)
- Images (.png, .jpg, .jpeg)

You can simply select multiple supported files during the upload process.
"""
        })

    if "supported file" in message or "file type" in message:

        return jsonify({
            "reply": """
The **Secure Data Anonymizer** supports the following file formats.

**Document Files**

- PDF (.pdf)
- Microsoft Word (.docx)
- Microsoft Excel (.xlsx)

**Image Files**

- PNG (.png)
- JPEG (.jpg, .jpeg)

These formats are supported for **OCR**, sensitive data detection, and document anonymization.
"""
        })

    if "how do i use" in message or "use this system" in message:

        return jsonify({
            "reply": """
Using the **Secure Data Anonymizer** is simple.

**Steps**

1. Upload one or more supported files.
2. Select a sector or use **Auto Detect**.
3. Start the anonymization process.
4. Review the detected personal data.
5. Check the privacy dashboard.
6. Download the anonymized document.
"""
        })

    # ===========================
    # Everything else goes to Gemini
    # ===========================

    reply = ask_gemini(message, context)

    return jsonify({"reply": reply})

@app.errorhandler(413)
def file_too_large(e):
    return render_template("upload.html", error="File is too large. Maximum size is 20MB.", sectors=SECTOR_RULES), 413

if __name__ == "__main__":
    app.run(debug=True)
