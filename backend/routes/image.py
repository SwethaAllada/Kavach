"""POST /analyze-image — screenshot upload -> OCR -> the same classifier.analyze()
every other channel uses.

Security / privacy:
  - Content-type is validated against an explicit allowlist (image/jpeg,
    image/png) before any processing.
  - Size is capped at 5MB; oversized uploads are rejected before the image
    bytes are even fully read into the vision call.
  - The image is held only in memory for the duration of the request — it is
    never written to disk and never sent to Supabase. Only the same
    whitelisted anonymized fields classifier.analyze() always logs (via
    core.privacy.to_anonymized_record) are persisted; the image itself and
    the extracted text are never part of that record.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, File, HTTPException, UploadFile

from models.schemas import ImageVerdict
from services.classifier import analyze as classifier_analyze
from services.vision import (
    VisionExtractionFailed,
    VisionUnavailable,
    extract_text_from_image,
)

log = logging.getLogger(__name__)

router = APIRouter()

_ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png"}
_MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5MB


@router.post("/analyze-image", response_model=ImageVerdict)
async def analyze_image(image: UploadFile = File(...)) -> ImageVerdict:
    if image.content_type not in _ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Unsupported image type '{image.content_type}'. "
                "Please upload a JPEG or PNG screenshot."
            ),
        )

    # Read in memory only — never written to disk. Bounded read: stop as
    # soon as we've seen more than the limit, so an oversized upload doesn't
    # get fully buffered before we reject it.
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await image.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_IMAGE_BYTES:
            raise HTTPException(
                status_code=413,
                detail="Image is too large. Please upload a screenshot under 5MB.",
            )
        chunks.append(chunk)
    image_bytes = b"".join(chunks)

    if not image_bytes:
        raise HTTPException(
            status_code=422,
            detail="Could not extract text from this image. Please paste the message text directly.",
        )

    try:
        extraction = extract_text_from_image(image_bytes, image.content_type)
    except VisionExtractionFailed:
        raise HTTPException(
            status_code=422,
            detail="Could not extract text from this image. Please paste the message text directly.",
        )
    except VisionUnavailable as e:
        log.warning("vision extraction unavailable: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Image analysis temporarily unavailable — please paste the message text directly.",
        )
    finally:
        # Discard the in-memory image bytes as soon as extraction is done
        # (success or failure) — nothing below this line references them.
        del image_bytes

    extracted_text = extraction["text"]
    extracted_sender = extraction["sender"]

    verdict = classifier_analyze(extracted_text)
    return ImageVerdict(
        **verdict,
        extracted_text=extracted_text,
        extracted_sender=extracted_sender,
    )
