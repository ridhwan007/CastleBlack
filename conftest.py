"""
Pytest configuration — sets up env vars required for import.
"""

import os

# Provide placeholder env vars so modules can be imported without a real config
os.environ.setdefault("AIPTT_AI_API_KEY",  "sk-ant-test-placeholder")
os.environ.setdefault("AIPTT_MASTER_KEY",  "a" * 64)  # 64 hex chars = 32 bytes
os.environ.setdefault("AIPTT_AUDIT_KEY",   "test-audit-key")
