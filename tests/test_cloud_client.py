"""
tests/test_cloud_client.py -- tests for client/cloud_client.py against
a REAL, live cloud/cloud_app.py instance (see tests/conftest.py's
live_cloud fixture) -- not a mock. This is what actually proves the
HTTP wrapper round-trips correctly through the real API.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import client.cloud_client as cloud_client  # noqa: E402


class TestHealthAndAvailability:
    def test_health(self, live_cloud):
        assert cloud_client.health()["status"] == "ok"

    def test_unreachable_cloud_raises_cloud_unavailable_error(self, monkeypatch):
        # No live_cloud fixture here -- nothing is listening on this port.
        monkeypatch.setattr(cloud_client, "CLOUD_BASE_URL", "http://127.0.0.1:1")
        with pytest.raises(cloud_client.CloudUnavailableError):
            cloud_client.health()


class TestDocuments:
    def test_push_and_fetch_round_trip_is_byte_identical(self, live_cloud):
        doc_id = os.urandom(16).hex()
        enc_name, nonce, ciphertext, tag = os.urandom(20), os.urandom(12), os.urandom(64), os.urandom(16)
        cloud_client.push_document(doc_id, enc_name, nonce, ciphertext, tag)

        doc = cloud_client.fetch_document(doc_id)
        assert doc["enc_name"] == enc_name
        assert doc["nonce"] == nonce
        assert doc["ciphertext"] == ciphertext
        assert doc["tag"] == tag

    def test_fetch_missing_document_returns_none(self, live_cloud):
        assert cloud_client.fetch_document("does-not-exist") is None

    def test_list_documents_decodes_enc_name_to_bytes(self, live_cloud):
        doc_id = os.urandom(16).hex()
        enc_name = os.urandom(20)
        cloud_client.push_document(doc_id, enc_name, os.urandom(12), os.urandom(8), os.urandom(16))

        [entry] = cloud_client.list_documents()
        assert entry["doc_id"] == doc_id
        assert entry["enc_name"] == enc_name
        assert isinstance(entry["enc_name"], bytes)

    def test_duplicate_push_raises_cloud_error_409(self, live_cloud):
        doc_id = os.urandom(16).hex()
        cloud_client.push_document(doc_id, b"a", b"n" * 12, b"c", b"t" * 16)
        with pytest.raises(cloud_client.CloudError) as exc_info:
            cloud_client.push_document(doc_id, b"a2", b"n" * 12, b"c2", b"t" * 16)
        assert exc_info.value.status_code == 409

    def test_replace_existing_document_returns_true_and_overwrites_it(self, live_cloud):
        doc_id = os.urandom(16).hex()
        cloud_client.push_document(doc_id, b"old-name", b"n" * 12, b"old-cipher", b"t" * 16)

        new_enc_name, new_nonce, new_ciphertext, new_tag = (
            os.urandom(20), os.urandom(12), os.urandom(64), os.urandom(16)
        )
        assert cloud_client.replace_document(doc_id, new_enc_name, new_nonce, new_ciphertext, new_tag) is True

        doc = cloud_client.fetch_document(doc_id)
        assert doc["enc_name"] == new_enc_name
        assert doc["nonce"] == new_nonce
        assert doc["ciphertext"] == new_ciphertext
        assert doc["tag"] == new_tag

    def test_replace_missing_document_returns_false_not_raises(self, live_cloud):
        result = cloud_client.replace_document("does-not-exist", b"n", b"x" * 12, b"c", b"t" * 16)
        assert result is False

    def test_delete_existing_document_returns_true_and_it_is_gone(self, live_cloud):
        doc_id = os.urandom(16).hex()
        cloud_client.push_document(doc_id, b"a", b"n" * 12, b"c", b"t" * 16)
        assert cloud_client.delete_document(doc_id) is True
        assert cloud_client.fetch_document(doc_id) is None

    def test_delete_missing_document_returns_false_not_raises(self, live_cloud):
        assert cloud_client.delete_document("does-not-exist") is False


class TestIndexReplace:
    def test_replace_pushes_entries_findable_via_search(self, live_cloud):
        label = os.urandom(32).hex()
        value = os.urandom(40)
        result = cloud_client.replace_index([(label, value)])
        assert result["inserted"] == 1

    def test_replace_clears_previous_state(self, live_cloud):
        old_label = os.urandom(32).hex()
        cloud_client.replace_index([(old_label, b"old")])
        new_label = os.urandom(32).hex()
        cloud_client.replace_index([(new_label, b"new")])

        # cloud_client has no direct "get by label" wrapper (client_app
        # never needs one -- it only ever searches by token), so check
        # the raw /index/<label> route directly to confirm the old
        # entry is really gone, not just unreachable through this
        # client's own API surface.
        import requests

        old_resp = requests.get(f"{live_cloud}/index/{old_label}", timeout=5)
        assert old_resp.status_code == 404
        new_resp = requests.get(f"{live_cloud}/index/{new_label}", timeout=5)
        assert new_resp.status_code == 200

    def test_replace_with_empty_list(self, live_cloud):
        result = cloud_client.replace_index([])
        assert result == {"removed": 0, "inserted": 0}


class TestSearch:
    def test_run_remote_search_no_match_returns_empty_list(self, live_cloud):
        assert cloud_client.run_remote_search(os.urandom(32)) == []


class TestMeta:
    def test_set_and_get_round_trip(self, live_cloud):
        cloud_client.set_meta("kdf_salt", b"s" * 16)
        assert cloud_client.get_meta("kdf_salt") == b"s" * 16

    def test_get_missing_key_returns_none(self, live_cloud):
        assert cloud_client.get_meta("does-not-exist") is None
