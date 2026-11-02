"""Encrypted Cloud Vault -- trusted client package.

Everything under `client/` runs on the trusted side of the boundary
described in Stage 1 (Section 02 of docs/architecture.html): it is the
only code in this project that ever holds a key or touches plaintext.
The cloud/ package (added in a later phase) must never import from here.
"""
