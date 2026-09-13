import os


BLOCKED_EXTENSIONS = {
    ".ade", ".apk", ".appx", ".bat", ".cmd", ".com", ".cpl", ".dll",
    ".dmg", ".exe", ".hta", ".jar", ".js", ".jse", ".msi", ".ps1",
    ".scr", ".sh", ".sys", ".vbe", ".vbs", ".wsf",
}
MACRO_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".ppsm"}
MAGIC_SIGNATURES = {
    b"MZ": "Windows executable header",
    b"\x7fELF": "Linux executable header",
    b"#!": "Script interpreter header",
}


def scan_upload(filename: str, payload: bytes) -> dict:
    """Perform conservative pre-encryption screening; this is not antivirus."""
    extension = os.path.splitext(filename.lower())[1]
    findings = []
    risk = "CLEAR"
    if extension in BLOCKED_EXTENSIONS:
        findings.append({"code": "EXECUTABLE_TYPE", "message": f"{extension} files are blocked by vault policy.", "severity": "BLOCK"})
        risk = "BLOCK"
    if extension in MACRO_EXTENSIONS:
        findings.append({"code": "MACRO_CAPABLE", "message": "Macro-enabled office content requires review before storage.", "severity": "REVIEW"})
        risk = "REVIEW" if risk == "CLEAR" else risk
    sample = payload[:8192].lstrip()
    for signature, message in MAGIC_SIGNATURES.items():
        if sample.startswith(signature) and extension not in BLOCKED_EXTENSIONS:
            findings.append({"code": "CONTENT_SIGNATURE", "message": message + " does not match a safe document profile.", "severity": "BLOCK"})
            risk = "BLOCK"
    if len(payload) == 0:
        findings.append({"code": "EMPTY_PAYLOAD", "message": "Empty files are not useful vault assets.", "severity": "REVIEW"})
        risk = "REVIEW" if risk == "CLEAR" else risk
    return {"risk": risk, "findings": findings, "scanned_bytes": min(len(payload), 8192)}
