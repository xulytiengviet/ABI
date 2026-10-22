"""ABI NEXUS DYELS engine API.

Runs the actual upstream Gigahorse -C Datalog storage client when installed.
No fake/synthetic DYELS responses. Does not accept arbitrary shell commands.
"""
from __future__ import annotations

import hmac
import os
import signal
import re
import shutil
import subprocess
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from normalizer import read_relations, normalize

ROOT = Path(os.getenv("GIGAHORSE_HOME", "/opt/gigahorse-toolchain")).resolve()
CLIENT = ROOT / "clients" / "abi_nexus_storage.dl"
SCRIPT = ROOT / "gigahorse.py"
TIMEOUT = min(300, max(15, int(os.getenv("ABI_ANALYSIS_TIMEOUT", "110"))))
ORIGINS = [
    origin.strip() for origin in os.getenv(
        "ABI_ALLOWED_ORIGINS",
        "https://xulytiengviet.github.io,http://localhost:8000,http://127.0.0.1:8000"
    ).split(",") if origin.strip()
]
TOKEN = os.getenv("ABI_API_KEY", "")
LOCK = threading.Lock()
MAX_BYTECODE_BYTES = 175_000
HEX_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})+$")

app = FastAPI(
    title="ABI NEXUS · DYELS Storage Analysis API",
    version="0.2.0",
    description="Isolated, read-only EVM runtime bytecode analysis via Gigahorse DYELS.",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


class AnalyzeRequest(BaseModel):
    bytecode: str = Field(min_length=4, max_length=2+2*MAX_BYTECODE_BYTES)


def is_ready() -> bool:
    return SCRIPT.is_file() and CLIENT.is_file() and shutil.which("uv") is not None and shutil.which("souffle") is not None


@app.get("/api/health")
def health():
    return {
        "engine": "gigahorse-dyels",
        "dyelsReady": is_ready(),
        "version": "0.2.0",
        "note": "Readiness checks executable paths, not a full analyzer smoke test.",
    }


def analyze_runtime(bytecode: str) -> dict:
    """Run one analysis with a unique filename and bounded subprocess lifetime.

    Gitahorse stores shared output metadata in working directories. A lock
    deliberately serializes requests to prevent cross-request contamination.
    """
    if not is_ready():
        raise HTTPException(503, detail="Gigahorse, Souffle, uv hoặc client DYELS chưa được cài đặt.")
    identifier = "abi_" + uuid.uuid4().hex
    input_dir = ROOT / ".abi-nexus-inputs"
    input_dir.mkdir(exist_ok=True)
    contract = input_dir / (identifier + ".hex")
    output_dir = ROOT / ".temp" / identifier / "out"
    # Clear stale results marker — no stale report will ever be considered success.
    contract.write_text(bytecode[2:] + "\n", encoding="ascii")
    command = [
        "uv", "run", "./gigahorse.py", "-j", "1",
        "-T", str(max(10, TIMEOUT-20)),
        "-C", "clients/abi_nexus_storage.dl",
        str(contract),
    ]
    try:
        proc = subprocess.Popen(
            command, cwd=str(ROOT), stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, text=True,
            start_new_session=True, env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        try:
            returncode = proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            # Terminate the whole job process group: uv -> Python -> Souffle.
            # A timeout must not leave an unbounded analysis running in the background.
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise HTTPException(504, detail="DYELS/Gigahorse vượt quá thời gian phân tích.") from exc
        if returncode != 0:
            raise HTTPException(
                502, detail="Gigahorse thực thi không thành công (exit "+str(returncode)+"). "
                            "Kiểm tra logs của backend và các phụ thuộc Soufflé.",
            )
        if not output_dir.is_dir():
            raise HTTPException(
                502, detail="Không tìm thấy thư mục kết quả Datalog; kiểm tra cấu hình đường dẫn .temp của Gigahorse."
            )
        try:
            relations = read_relations(output_dir)
        except ValueError as exc:
            raise HTTPException(502, detail=str(exc)) from exc
        if not relations:
            raise HTTPException(
                502, detail="Gigahorse không xuất quan hệ DYELS; không thể khẳng định phục hồi thành công."
            )
        return normalize(relations, (len(bytecode)-2)//2)
    finally:
        try:
            contract.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            if output_dir.parent.is_dir():
                shutil.rmtree(output_dir.parent)
        except OSError:
            pass


@app.post("/api/analyze")
def analyze(payload: AnalyzeRequest, request: Request):
    if TOKEN:
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or not hmac.compare_digest(authorization[7:], TOKEN):
            raise HTTPException(401, detail="Yêu cầu Bearer token hợp lệ.")
    if not HEX_RE.fullmatch(payload.bytecode):
        raise HTTPException(422, detail="Bytecode phải là chuỗi hex 0x có độ dài chẵn.")
    if len(payload.bytecode) > 2 + MAX_BYTECODE_BYTES*2:
        raise HTTPException(413, detail="Bytecode vượt giới hạn 175 KB.")
    if not LOCK.acquire(blocking=False):
        raise HTTPException(429, detail="Backend đang phân tích hợp đồng khác; thử lại sau.")
    try:
        return analyze_runtime(payload.bytecode)
    finally:
        LOCK.release()
