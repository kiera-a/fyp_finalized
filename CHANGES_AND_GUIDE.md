# GRC Sector Anonymisation Tool — Changes & Guide

_Last updated: 2026-07-02_

This guide documents the recent work on the tool: the **multi-file / zip-folder
upload** feature and the **pandas warning cleanup**. It covers what was broken,
what changed, how the new flow works, and how to run and test it.

---

## 1. What the tool does

A Flask web app that:
- Accepts `txt, csv, xlsx, pdf, docx, zip` and images (`png/jpg/jpeg/webp/bmp/tiff/tif`, via OCR).
- Auto-detects the GRC sector (**Banking**, **Healthcare**, **IT/Cybersecurity**).
- Lets the user choose which sensitive items to protect and which technique applies.
- Anonymises the data and shows a risk dashboard, k-anonymity preview, and before/after preview.
- Returns the anonymised result for download.

Main files:
- `app.py` — Flask routes + file reading/writing.
- `anonymizer.py` — detection rules, patterns, and anonymisation logic.
- `templates/` — `upload.html`, `options.html`, `preview.html`.

---

## 2. The goal

Support **multiple file uploads and zip folders**: detect the sector across the
whole batch and return an anonymised output **for each file, in the same format it
was uploaded in**.

---

## 3. What was broken (before)

| # | Problem | Effect |
|---|---------|--------|
| 1 | `/upload` redirected to `/select`, and `options.html` posted to `/change-sector`, but **neither route existed** in `app.py`. `options.html` was never rendered. | **Every upload 404'd** immediately after selecting files. |
| 2 | `_write_output` only handled `txt/csv/xlsx/pdf`. For `zip`, `png`, `docx`, etc. it wrote nothing, then `zipf.write(output_path, ...)` failed. | Uploading a **zip or image crashed** `/process` with `FileNotFoundError`. |
| 3 | A `.zip` was flattened into a single text blob. | You never got your **individual files back**. |
| 4 | In `/process`, `all_df` was overwritten every loop iteration, and the final dashboard mixed `before_counts` from only the **last** file with `after_counts` from the **combined** text. | **Wrong risk numbers.** |
| 5 | `anonymize_dataframe` mutated the frame column-by-column (`out[col] = ...`). | Flooded the console with pandas `FutureWarning: ChainedAssignmentError`. |

---

## 4. What was fixed (after)

### 4.1 Multi-file & zip support (`app.py`)

Every upload is now modelled as a flat list of **documents**:
- a normal file → **one** document,
- a `.zip` folder → **one document per readable file inside it**,
- an image → one document whose text comes from OCR.

This is the single idea that makes all the goals work together: sectors are detected
across the whole batch, yet each file is still handled — and returned — on its own.

New helpers in `app.py`:
- `_expand_zip(filepath)` — yields one document per readable file inside a zip.
- `_collect_documents(files)` — reads every saved upload from disk into documents (expanding zips).
- `_aggregate_detected(documents, sector)` — sums sensitive-item counts across all documents.
- `_combined_text_and_columns(documents)` — combined text + all column names for sector detection.
- `_combined_dataframe(documents)` — merges tabular documents (used for the k-anonymity preview).

New / rewritten routes:
- **`GET /select`** _(added)_ — renders `options.html` from the session. Fixes the 404.
  Adds a **"Same as uploaded file(s)"** output option (default) alongside txt/csv/xlsx/pdf.
- **`POST /change-sector`** _(added)_ — re-detects sensitive items when the user switches sector.
- **`POST /process`** _(rewritten)_ — anonymises each document independently, writes each in its
  own format (or a single user-chosen format), and bundles the results:
  - **1 file** → returned directly (e.g. `anonymized_01_customers.csv`).
  - **many files** → zipped together as `anonymized_files.zip`.
  - Dashboard, k-anonymity, and total-changes are computed from **correctly aggregated**
    before/after counts.

Hardened:
- **`_write_output`** now falls back to `.txt` for any format it can't rebuild
  (zip/docx/image) — no more crashes.
- Each upload's original filename is stored in the session so outputs get clean names.

`upload.html` already had `multiple` on the file input and needed no change.
`options.html` needed no change — its output-format dropdown just receives the new
`original` option.

### 4.2 Pandas warning cleanup (`anonymizer.py`)

The warning came from pandas steering toward **Copy-on-Write** (the pandas 3.0 default).
`anonymize_dataframe` used to copy the frame and mutate it column-by-column, which tripped
the chained-assignment heuristic (using `.loc[:, col]` instead only swapped it for a
_dtype-change_ warning).

**Fix:** build each anonymised column into a dict and assemble a **fresh DataFrame in one
step** (`pd.DataFrame(new_cols, index=df.index)`). This is Copy-on-Write safe and avoids
both warnings. Added `import pandas as pd` to `anonymizer.py`. Anonymisation output is
unchanged, and the original DataFrame is now provably left untouched.

---

## 5. How to run

```bash
# 1. Install dependencies
pip install -r requirements.txt
#    (On Python 3.14, Pillow 10.4 won't build — a newer Pillow works fine.)
#    For image OCR, also install the Tesseract OCR engine and restart the terminal.

# 2. Start the app
python app.py

# 3. Open in a browser
http://127.0.0.1:5000
```

**Usage:** drag in one or more files (or a `.zip`) → pick a sector or leave on
Auto-detect → review the detected risks and choose what to protect → pick an output
format (default keeps each file's own format) → tick consent → Anonymize → download.

---

## 6. How to test

**End-to-end (Flask test client)** — drives `/upload → /select → /process → /getfile`
for a mixed `csv + txt` batch and for a `.zip` folder. Verifies redirects, that
`/select` renders, that per-file formats are preserved, and that bank account /
password / NRIC are actually masked.

```bash
# Run with FutureWarning promoted to an error to prove the warning is gone:
python -W error::FutureWarning smoke_test.py
```

Expected: **all checks PASS**, and a multi-file upload produces
`anonymized_files.zip` containing one anonymised file per input, each in its original
format (e.g. `anonymized_01_customers.csv`, `anonymized_02_notes.txt`). A `.zip` upload
expands into separate output files.

Quick manual check of the warning fix:

```bash
python -W error::FutureWarning -c "import pandas as pd; from anonymizer import anonymize_dataframe; \
print(anonymize_dataframe(pd.DataFrame({'customer_name':['John Tan'],'bank_account':[12345678]}), ['name','bank_account']).to_string(index=False))"
```

---

## 7. Changed files at a glance

| File | Change |
|------|--------|
| `app.py` | Added `/select`, `/change-sector`; rewrote `/process`; added document-model helpers; hardened `_write_output`; store original filenames. |
| `anonymizer.py` | Rewrote `anonymize_dataframe` to build a fresh DataFrame (Copy-on-Write safe); added `import pandas as pd`. |
| `templates/` | No changes required. |

---

## 8. Known / out of scope

- Images are OCR'd to text and returned as `.txt` — the original image is not visually
  redacted (documented behaviour in `README.txt`).
- `docx` inputs are read for text and returned as `.txt` (there is no docx writer).
- A `.zip` output preserves each inner file's original format; formats that can't be
  rebuilt fall back to `.txt`.
