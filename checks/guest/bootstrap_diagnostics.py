"""Bounded early-start observations on an independent, owned COM2 UART.

These markers are diagnostic only. They never establish supervisor HELLO,
Windows boot acceptance, account identity, activation, or a successful test.
Raw bytes stay in a fixed-size QEMU ring buffer, never in a growing file.
"""
from __future__ import annotations

import base64
import re


def emit_terminal_summary(capture, qmp, emit) -> None:
    """Diagnostic exceptions, including serialization/output, never stop cleanup."""
    try:
        if capture is not None:
            capture.observe(qmp)
            emit("guest_bootstrap_summary", **capture.summary())
    except Exception:
        pass


def specialize_command() -> str:
    # An additional best-effort observation after the existing specialize
    # commands. This process always exits zero and changes no Windows policy.
    script = ("try{$p=[IO.Ports.SerialPort]::new('COM2',115200);$p.WriteTimeout=250;"
              "$p.Open();$p.WriteLine('GUEST_BOOTSTRAP_V1 0 0')}catch{}"
              "finally{if($p){try{$p.Dispose()}catch{}}};exit 0")
    return 'powershell.exe -NoProfile -NonInteractive -Command "' + script + '"'


def first_logon_script() -> str:
    # Keep the original discovery, ownership-tag guard, launch arguments,
    # inherited token and immediate return. Each marker closes COM2 before
    # the next stage; the parent never waits for the supervisor to exit.
    return ("$ErrorActionPreference='Stop';function m($s,$c=0){$p=$null;try{"
            "$p=[IO.Ports.SerialPort]::new('COM2',115200);$p.WriteTimeout=250;$p.Open();"
            "$p.WriteLine(('GUEST_BOOTSTRAP_V1 {0} {1}' -f $s,$c))}catch{}"
            "finally{if($p){try{$p.Dispose()}catch{}}}};m 1;try{"
            "$v=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=5'|"
            "Where-Object VolumeName -eq 'SESSIONPAYLOAD');m 2 $v.Count;"
            "if($v.Count -ne 1){exit 71};$r=$v[0].DeviceID+'\\';"
            "if(!(Test-Path ($r+'guest-contract.tag'))){m 3 0;exit 72};m 3 1;m 4;"
            "Start-Process -FilePath ($r+'dotnet\\dotnet.exe') "
            "-ArgumentList @(($r+'GuestSupervisor.dll'),'--media-root',$r) -WindowStyle Hidden"
            "}catch{m 5 $_.Exception.HResult;exit 73}")


class BootstrapCapture:
    RING_BYTES = 4096
    MAX_BYTES = 8192
    MAX_RECORDS = 16
    MAX_LINE = 128
    # 0: specialize command; 1-5: PowerShell; 10-18: managed supervisor.
    ZERO_CODES = frozenset({0, 1, 4, 10, 12, 13, 14, 15, 16})
    ERROR_CODES = frozenset({5, 17, 18})

    def __init__(self):
        self.offset = 0
        self.buffer = bytearray()
        self.discarding_line = False
        self.records = []
        self.pending = []
        self.rejected = 0
        self.byte_limit = False
        self.record_limit = False
        self.read_error = None
        self.capture_attempted = False

    def _reject(self) -> None:
        self.rejected = min(1024, self.rejected + 1)

    def _line(self, line: bytes) -> None:
        line = line.rstrip(b'\r')
        if not line:
            return
        match = re.fullmatch(rb'GUEST_BOOTSTRAP_V1 ([0-9]{1,2}) (-?[0-9]{1,10})', line)
        if len(line) > self.MAX_LINE or match is None:
            self._reject()
            return
        stage, code = map(int, match.groups())
        valid = ((stage in self.ZERO_CODES and code == 0) or
                 (stage in self.ERROR_CODES and -(2**31) <= code < 2**31) or
                 (stage == 2 and 0 <= code <= 26) or (stage == 3 and code in {0, 1}) or
                 (stage == 11 and code in {0, 64}))
        if not valid:
            self._reject()
            return
        if len(self.records) == self.MAX_RECORDS:
            self.record_limit = True
            return
        value = {'stage_id': stage, 'code': code}
        self.records.append(value)
        self.pending.append(value)

    def feed(self, data: bytes) -> None:
        remaining = max(0, self.MAX_BYTES - self.offset)
        accepted = data[:remaining]
        self.offset += len(data)
        if len(data) > remaining:
            self.byte_limit = True
        self.buffer.extend(accepted)
        while True:
            end = self.buffer.find(b'\n')
            if end < 0:
                if len(self.buffer) > self.MAX_LINE:
                    if not self.discarding_line:
                        self._reject()
                    self.buffer.clear()
                    self.discarding_line = True
                return
            line = bytes(self.buffer[:end])
            del self.buffer[:end + 1]
            if self.discarding_line:
                self.discarding_line = False
            else:
                self._line(line)

    def observe(self, qmp) -> list[dict]:
        # Exactly one terminal read, after the experiment's outcome is known.
        # No extra QMP operation is introduced into the live test path.
        if not self.capture_attempted:
            self.capture_attempted = True
            try:
                value = qmp.call("ringbuf-read", {"device": "bootstrap0", "size": self.RING_BYTES, "format": "base64"})
                if not isinstance(value, str) or len(value) > ((self.RING_BYTES + 2) // 3) * 4:
                    raise ValueError()
                data = base64.b64decode(value, validate=True)
                if len(data) > self.RING_BYTES:
                    raise ValueError()
                self.feed(data)
            except Exception:
                self.read_error = 1  # capture unavailable; no raw exception text
        result, self.pending = self.pending, []
        return result

    def summary(self) -> dict:
        return {'diagnostic_only': True, 'emitter_identity_verified': False,
                'capture_scope': 'terminal_ring_snapshot', 'ring_capacity_bytes': self.RING_BYTES,
                'ring_overwrite_not_observable': True, 'capture_attempted': self.capture_attempted,
                'observations': list(self.records), 'rejected_lines': self.rejected,
                'byte_limit_reached': self.byte_limit, 'record_limit_reached': self.record_limit,
                'incomplete_line': bool(self.buffer) or self.discarding_line, 'read_error': self.read_error}
