GRC Sector Anonymisation Tool - Fixed A+ Version

Run:
1. pip install -r requirements.txt
2. python app.py
3. Open http://127.0.0.1:5000

Fixes in this version:
- Preview dashboard layout fixed and neatly aligned.
- Metric font sizes are responsive and fit inside cards.
- k-anonymity cards have separate sizing.
- Risk After now uses residual risk logic based on selected anonymisation technique strength.
- Same dark purple/pink UI style is preserved.
- Supports Banking, Healthcare and IT/Cybersecurity sector rules.
- Supports txt, csv, xlsx, pdf, docx and zip.


OCR IMAGE SUPPORT
- This version accepts .png, .jpg, .jpeg, .webp, .bmp, .tiff and .tif image files.
- The system uses OCR to extract text from the image, then applies the same GRC sector detection and anonymisation workflow.
- To use OCR locally, install the Python requirements and install the Tesseract OCR engine on your computer.
  Windows: install Tesseract OCR, then restart VS Code/terminal before running python app.py.
- For images, the anonymised output is generated as text/CSV/XLSX/PDF based on selected output format. The original image itself is not visually redacted in this version.
