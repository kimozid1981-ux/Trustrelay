"""QR-code analysis: decode payload (server-side from an uploaded image, or client-decoded text) and classify it."""

from __future__ import annotations

import io
import re

import numpy as np

from app.analysis.extract import extract_ibans
from app.analysis.types import AnalysisContext, Confidence, Finding, Severity


def decode_qr_png(png: bytes) -> list[str]:
    import cv2
    from PIL import Image

    img = Image.open(io.BytesIO(png)).convert("RGB")
    arr = np.array(img)[:, :, ::-1]
    detector = cv2.QRCodeDetector()
    ok, decoded, _, _ = detector.detectAndDecodeMulti(arr)
    if ok:
        return [d for d in decoded if d]
    data, _, _ = detector.detectAndDecode(arr)
    return [data] if data else []


def classify_payload(ctx: AnalysisContext, payload: str) -> None:
    """Populate ctx (urls / ibans / text) from a QR payload and add explanatory findings."""
    ctx.qr_payload = payload[:4000]
    lower = payload.strip().lower()
    if lower.startswith(("http://", "https://")) or re.match(r"^[\w.-]+\.[a-z]{2,}(/|$)", lower):
        ctx.urls.append(payload.strip())
        ctx.add(Finding("qr", "qr_contains_link", Severity.INFO, Confidence.HIGH, "qr_decoder", [payload[:200]]))
    elif payload.startswith("BCD\n") or payload.startswith("BCD\r\n"):
        # EPC069-12 SEPA credit transfer QR ("GiroCode")
        lines = payload.splitlines()
        name = lines[5] if len(lines) > 5 else ""
        iban = lines[6].replace(" ", "") if len(lines) > 6 else ""
        amount = lines[7] if len(lines) > 7 else ""
        if iban:
            ctx.ibans.append(iban)
        ctx.text = "\n".join(x for x in (ctx.text, f"Bénéficiaire: {name}", f"Montant: {amount}") if x)
        ctx.add(Finding("qr", "qr_payment_request", Severity.INFO, Confidence.HIGH, "qr_decoder", [name[:70], amount[:20]]))
    elif lower.startswith(("smsto:", "sms:", "tel:")):
        ctx.add(Finding("qr", "qr_triggers_sms_or_call", Severity.MODERATE, Confidence.MEDIUM, "qr_decoder", [payload[:100]]))
    elif lower.startswith("wifi:"):
        ctx.add(Finding("qr", "qr_wifi_network", Severity.INFO, Confidence.HIGH, "qr_decoder", []))
    elif lower.startswith(("bitcoin:", "ethereum:", "litecoin:", "usdt:")):
        ctx.add(Finding("qr", "qr_crypto_payment", Severity.STRONG, Confidence.MEDIUM, "qr_decoder", [payload[:60]]))
    elif lower.startswith("otpauth:"):
        ctx.add(Finding("qr", "qr_authenticator_setup", Severity.STRONG, Confidence.MEDIUM, "qr_decoder", []))
    else:
        ctx.text = "\n".join(x for x in (ctx.text, payload) if x)
        ctx.ibans.extend(i for i in extract_ibans(payload) if i not in ctx.ibans)
        ctx.add(Finding("qr", "qr_contains_text", Severity.INFO, Confidence.HIGH, "qr_decoder", [payload[:120]]))
