"""P4 Test Audit: inspects existing test assertions and generates executable proof tests for confirmed flaws."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .discovery import read_text
from .llm_client import LLMClient
from .multipass import GroundedFinding

TEST_SYNTHESIS_SYSTEM = """You are a Principal Test Automation and Verification Engineer.
Given a confirmed bug or security vulnerability in a source file, write a MINIMAL, executable reproduction test
using Python's standard `unittest` framework.

Requirements:
1. The test must specifically trigger the defect described.
2. It should fail when the defect is present, and pass once the defect is fixed.
3. Import the target function cleanly using standard module conventions.
4. Reply with ONLY valid Python test code in a single fenced code block ```python ... ```.
"""


@dataclass
class TestAuditResult:
    total_test_files: int
    assert_count: int
    mock_count: int
    superficial_tests: List[str]
    generated_tests: List[str]


def audit_test_suite(test_files: List[Path]) -> TestAuditResult:
    """Analyze test files for assertion density and superficial test patterns."""
    assert_count = 0
    mock_count = 0
    superficial = []

    for tf in test_files:
        code = read_text(tf) or ""
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = ""
                    if isinstance(node.func, ast.Attribute):
                        name = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        name = node.func.id
                    if name.startswith("assert") or name == "assertTrue" or name == "assertEqual":
                        assert_count += 1
                    if "mock" in name.lower() or "patch" in name.lower():
                        mock_count += 1
        except Exception:
            pass

        # Flag tests with zero assertions
        if "assert" not in code:
            superficial.append(f"{tf.name}: Contains no assert statements")

    return TestAuditResult(
        total_test_files=len(test_files),
        assert_count=assert_count,
        mock_count=mock_count,
        superficial_tests=superficial,
        generated_tests=[],
    )


def generate_repro_test(
    finding: GroundedFinding, source_code: str, client: LLMClient
) -> Optional[str]:
    """Synthesize an executable reproduction test for a confirmed flaw."""
    if finding.verification_status != "confirmed" or not client.is_available:
        return None

    prompt = (
        f"File: {finding.file}\n"
        f"Flaw: {finding.claim}\n"
        f"Cited Lines: {finding.line_start}-{finding.line_end}\n"
        f"Evidence: {finding.evidence}\n"
        f"Scenario: {finding.failure_scenario}\n\n"
        f"<source_code>\n{source_code[:8000]}\n</source_code>"
    )

    resp = client.chat_complete(TEST_SYNTHESIS_SYSTEM, prompt, temperature=0.1, max_tokens=1500)
    if not resp:
        return None

    m = re.search(r"```(?:python)?\s*([\s\S]*?)\s*```", resp)
    return m.group(1).strip() if m else None
