# Integration Tests

These tests require a live lab environment (VMs with AD, target hosts).

They are excluded from CI (`pytest -m "not integration"`).

## Setup

1. Configure `.env` with `AIPTT_AI_API_KEY`, `AIPTT_MASTER_KEY`, `AIPTT_AUDIT_KEY`
2. Start lab VMs
3. Run: `pytest tests/integration/ -v`
