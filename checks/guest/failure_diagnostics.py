"""Failure-only observations of our one disposable display; never pass evidence.

Raw pixels and OCR words are private, temporary inputs. Only fixed label IDs,
bounded counters, dimensions, and QEMU's documented state enum leave this file.
"""
from __future__ import annotations

import math
import re
import stat
from pathlib import Path

RUN_STATES = frozenset({"debug", "inmigrate", "internal-error", "io-error", "paused", "postmigrate",
    "prelaunch", "finish-migrate", "restore-vm", "running", "save-vm", "shutdown", "suspended",
    "watchdog", "guest-panicked", "colo"})

LABELS = (
    ("windows_problem_message", r"\b(?:your (?:device|pc) ran into a problem|your device needs to restart)\b"),
    ("windows_stop_code_label", r"\bstop code\b"),
    ("windows_recovery_message", r"\b(?:your pc (?:could not|couldn t) start properly|automatic repair|recovery your pc)\b"),
    ("windows_setup_label", r"\bwindows setup\b"),
    ("windows_installing_label", r"\binstalling windows\b"),
    ("windows_activation_label", r"\b(?:activate windows|windows activation|activation settings)\b"),
    ("oobe_account_label", r"\b(?:let s add your microsoft account|sign in with microsoft)\b"),
    ("oobe_region_label", r"\bis this the right country or region\b"),
    ("uefi_no_bootable_message", r"\bno bootable option (?:or device )?was found\b"),
    ("uefi_shell_label", r"\buefi interactive shell\b"),
    ("stock_cd_boot_prompt", r"\bpress any key to boot from cd or dvd\b"),
)


def query_state(qmp) -> dict:
    try:
        value = qmp.call("query-status")
        if not isinstance(value, dict) or type(value.get("running")) is not bool or value.get("status") not in RUN_STATES:
            return {"query_succeeded": False}
        return {"query_succeeded": True, "running": value["running"], "status": value["status"]}
    except Exception:
        return {"query_succeeded": False}


def classify_tsv(raw: bytes) -> dict:
    if len(raw) > 65536:
        raise ValueError("ocr_output_limit")
    lines = raw.decode("utf-8", errors="strict").splitlines()
    if not lines or lines[0] != "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext" or len(lines) > 2049:
        raise ValueError("ocr_format_invalid")
    words = []
    rows = 0
    for line in lines[1:]:
        if len(line) > 2048:
            raise ValueError("ocr_row_limit")
        fields = line.split("\t", 11)
        if len(fields) != 12:
            raise ValueError("ocr_row_invalid")
        if fields[0] != "5":
            continue
        rows += 1
        confidence = float(fields[10])
        if not math.isfinite(confidence) or not -1 <= confidence <= 100:
            raise ValueError("ocr_confidence_invalid")
        if confidence >= 65:
            # This private scratch text is never returned, logged, or written.
            words.append(re.sub(r"[^a-z0-9]+", " ", fields[11].lower()).strip())
    text = " ".join(words)
    return {"word_rows": rows, "confident_word_rows": len(words),
            "fixed_label_ids": [name for name, pattern in LABELS if re.search(pattern, text)]}


def ppm_dimensions(path: Path) -> tuple[int, int]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16 * 1024 * 1024:
        raise ValueError("screen_file_size_invalid")
    with path.open("rb") as stream:
        prefix = stream.read(256)
    # QEMU 8.2 screendump's binary PPM header is exactly this form. Unknown
    # formats are rejected before invoking the OCR decoder, not guessed.
    header = re.match(rb"P6\n([0-9]{1,4}) ([0-9]{1,4})\n255\n", prefix)
    if header is None:
        raise ValueError("screen_format_invalid")
    width, height = map(int, header.groups())
    if not (0 < width <= 4096 and 0 < height <= 4096 and info.st_size == header.end() + width * height * 3):
        raise ValueError("screen_dimensions_invalid")
    return width, height


def observe_failure(qmp, work: Path, deadline, command) -> dict:
    result = {"diagnostic_only": True, "vm_state": query_state(qmp), "screen_capture_succeeded": False,
              "ocr_succeeded": False, "fixed_label_ids": [], "temporary_image_removed": False}
    image = work / "failure-display.ppm"
    created = False
    try:
        if image.exists():
            result["diagnostic_category"] = "own_screen_path_collision"
            return result
        # The QMP API has no file-size argument. The subsequent size/pixel cap
        # bounds OCR input, not QEMU's own file-creation operation. QMP has a
        # five-second reply deadline, and this is our single owned display.
        created = True
        qmp.call("screendump", {"filename": str(image), "format": "ppm"})
        width, height = ppm_dimensions(image)
        result.update(screen_capture_succeeded=True, width=width, height=height)
        raw = command(["tesseract", str(image), "stdout", "-l", "eng", "--psm", "11", "tsv"],
                      deadline, 10, maximum_output_bytes=65536)
        result.update(classify_tsv(raw))
        result["ocr_succeeded"] = True
        result["diagnostic_category"] = "fixed_labels_observed" if result["fixed_label_ids"] else "no_supported_label_observed"
    except Exception:
        # Do not expose a tool message, path, screenshot, arbitrary OCR word,
        # numeric text from a screen, or infer a cause from an unavailable image.
        result["diagnostic_category"] = "screen_or_ocr_unavailable"
    finally:
        if created:
            try:
                image.unlink(missing_ok=True)
                result["temporary_image_removed"] = not image.exists()
            except Exception:
                result["temporary_image_removed"] = False
        # Remaining owned files are still covered by the host's final rmtree.
    return result
