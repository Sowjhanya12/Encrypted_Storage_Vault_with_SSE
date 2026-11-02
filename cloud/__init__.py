"""Encrypted Cloud Vault -- untrusted cloud package.

Everything under `cloud/` runs on the untrusted side of the trust
boundary described in Stage 1 (Section 02 of docs/architecture.html):
it holds zero keys, never sees plaintext, and must never import from
client/. If code in this package ever needs something from
client.crypto or client.keymgmt, that is a sign the trust boundary has
been crossed by mistake, not a dependency to add.
"""
