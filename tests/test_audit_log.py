"""Week 3 deliverable: HMAC audit log chain tests.

Implement clean-chain verification and tamper detection. See the guide's
tests/test_audit_log.py examples (clean chain verifies, tampered entry
caught at the correct line).

TODO (Week 3):
- test_chain_verifies_clean_log
- test_chain_detects_tampered_entry
- test_first_entry_prev_hmac_is_genesis
- test_different_key_fails_verification
"""

import pytest

pytestmark = pytest.mark.skip(
    reason="Week 3: implement audit log tests per LIDAS_Intern_Guide"
)
