from uuid import UUID
from fastapi.responses import PlainTextResponse, HTMLResponse
from fastapi import APIRouter, UploadFile, File, Form, Request
from fastapi.templating import Jinja2Templates
import os, uuid, tempfile, sys
from mysecscan.scan_engine import scan_file
from mysecscan.reporters.console_reporter import print_vulnerabilities
from mysecscan.models import SessionLocal, ScanResult
from fastapi import HTTPException


from io import StringIO



base_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(base_dir, "templates")
templates = Jinja2Templates(directory=template_dir)
router = APIRouter()

@router.post("/scan",     
    summary="Scan dependency files for known vulnerabilities",
    description="Upload a dependency file (e.g. requirements.txt) and specify the ecosystem (e.g. PyPI, npm). Returns a plain-text vulnerability report.",
    response_class=PlainTextResponse,
    )
async def scan(file: UploadFile = File(...), ecosystem: str = Form("PyPI")):
    scan_id = uuid.uuid4()
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"{scan_id}_{file.filename}")

    with open(temp_path, "wb") as f:
        f.write(await file.read())

    results = scan_file(temp_path, ecosystem)

    # 🎯 This captures the console output only
    buf = StringIO()
    sys.stdout = buf
    print_vulnerabilities(results)
    sys.stdout = sys.__stdout__
    final_output = buf.getvalue()

    # Save that string in DB wrapped in a JSON object
    db = SessionLocal()
    try:
        db.add(ScanResult(
            id=scan_id,
            uploaded_filename=file.filename,
            ecosystem=ecosystem,
            results={"report": final_output}
        ))
        db.commit()
    finally:
        db.close()

    # ✅ Only return the human-readable output
    return PlainTextResponse(f"{final_output}\n\n🔗 View online: https://hookcrate.io/scan/{scan_id}", media_type="text/plain")

@router.get("/secscan", include_in_schema=False)
def secscan(request: Request):
    return templates.TemplateResponse("secscan.html", {"request": request})
    
@router.get("/result-mockup", include_in_schema=False)
def mock_scan(request: Request):
    return templates.TemplateResponse("result_mockup.html", {"request": request})
    
@router.get("/submit-mockup", include_in_schema=False)
def mock_scan(request: Request):
    return templates.TemplateResponse("submit_mockup.html", {"request": request})
    
@router.get("/scan/{scan_id}", response_class=HTMLResponse)
def view_scan(scan_id: str, request: Request):
    db = SessionLocal()
    try:
        scan = db.query(ScanResult).filter(ScanResult.id == UUID(scan_id)).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return templates.TemplateResponse(
            "scan_summary.html",
            {"request": request, "scan_id": scan_id, "scan": scan},
            media_type="text/html"
            )

    finally:
        db.close()

