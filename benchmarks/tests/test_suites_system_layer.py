"""
Self-tests for the system-layer harness (LiveCloud, wire capture) and for
suites B4-B6.

Same principle as the primitive-layer tests: these do not assert that the
vault is fast. They assert that the suites measure the real two-process
system and that their correctness gates genuinely fire -- because a
system benchmark that quietly measured an empty vault, a failed upload or
a zero-result search would produce plausible numbers that mean nothing.

Everything runs at a deliberately tiny sizing against throwaway vaults in
temporary directories.
"""

import dataclasses
import os

import pytest

from benchmarks import config
from benchmarks.config import SMOKE
from benchmarks.harness.cloud_process import (
    BENCHMARK_HTTP_TIMEOUT_SECONDS,
    SHIPPED_HTTP_TIMEOUT_SECONDS,
    LiveCloud,
)
from benchmarks.harness.recorder import (
    PHASE_MEASURE,
    Recorder,
    load_raw,
    measured_values,
    scalar_values,
)
from benchmarks.harness.wire import record_wire
from benchmarks.suites import b4_upload_rebuild, b5_search, b6_storage

TINY = dataclasses.replace(
    SMOKE,
    name="tiny-system",
    description="self-test sizing -- not a measurement",
    upload_max_documents=4,
    rebuild_checkpoints=(2, 4),
    rebuild_repeats=1,
    search_match_counts=(1, 2),
    search_repeats=2,
    search_scaling_corpus_sizes=(4,),
    search_scaling_fixed_k=2,
    storage_corpus_size=4,
    default_warmup=1,
)


def _run_suite(module, tmp_path, profile=TINY):
    recorder = Recorder(str(tmp_path), profile.name, {"self_test": True}, config.SUITE_IDS)
    recorder.begin_suite(module.SUITE_ID)
    metadata = module.run(recorder, profile)
    recorder.end_suite(module.SUITE_ID)
    recorder.finalize(extra={"suite_metadata": {module.SUITE_ID: metadata}})
    return metadata, load_raw(str(tmp_path), module.SUITE_ID)


@pytest.fixture(scope="module")
def b4_result(tmp_path_factory):
    return _run_suite(b4_upload_rebuild, tmp_path_factory.mktemp("b4"))


@pytest.fixture(scope="module")
def b5_result(tmp_path_factory):
    return _run_suite(b5_search, tmp_path_factory.mktemp("b5"))


@pytest.fixture(scope="module")
def b6_result(tmp_path_factory):
    return _run_suite(b6_storage, tmp_path_factory.mktemp("b6"))


# ---------------------------------------------------------------------------
# harness: the live cloud process and wire capture
# ---------------------------------------------------------------------------

class TestLiveCloudProcess:
    def test_starts_a_real_separate_process_and_serves_health(self):
        import urllib.request

        with LiveCloud() as cloud:
            assert cloud.process.pid != os.getpid()
            assert cloud.process.poll() is None
            with urllib.request.urlopen(f"{cloud.base_url}/health", timeout=5) as r:
                assert b"untrusted-cloud" in r.read()

    def test_points_cloud_client_at_itself_and_restores_afterwards(self):
        import client.cloud_client as cloud_client

        before = cloud_client.CLOUD_BASE_URL
        with LiveCloud() as cloud:
            assert cloud_client.CLOUD_BASE_URL == cloud.base_url
        assert cloud_client.CLOUD_BASE_URL == before, (
            "a benchmark must never leave the client module aimed at a dead server"
        )

    def test_process_is_terminated_and_database_removed_on_exit(self):
        with LiveCloud() as cloud:
            process, db_path = cloud.process, cloud.db_path
            assert os.path.exists(db_path)
        assert process.poll() is not None
        assert not os.path.exists(db_path)

    def test_a_server_that_cannot_start_raises_with_its_output(self):
        cloud = LiveCloud(db_path="/nonexistent-directory/vault.sqlite3")
        with pytest.raises(RuntimeError) as excinfo:
            cloud.__enter__()
        assert "cloud process" in str(excinfo.value)


class TestBenchmarkTimeoutOverride:
    """The one documented deviation from the shipped client.

    `client/cloud_client.py` ships a 10-second per-request timeout. That
    threshold ended the authoritative B4 run at document 81 of 200 on a
    request that stalled for environmental reasons -- the evidence showed the
    workload's largest single request is sub-second, so the timeout was
    detecting an OS stall, not a slow system under test. LiveCloud therefore
    raises it for the duration of a benchmark and restores it afterwards.

    These tests exist because an override that leaked would be far worse than
    the problem it solves: it would silently change the shipped application's
    behaviour for every later caller in the same process.
    """

    def test_the_shipped_value_is_what_the_application_actually_ships(self):
        """The harness constant must describe the real module, not drift from
        it -- otherwise the manifest would report a shipped value that is not
        the shipped value."""
        import client.cloud_client as cloud_client

        assert cloud_client._TIMEOUT_SECONDS == SHIPPED_HTTP_TIMEOUT_SECONDS == 10

    def test_original_value_is_saved_and_the_benchmark_value_applied(self):
        import client.cloud_client as cloud_client

        original = cloud_client._TIMEOUT_SECONDS
        with LiveCloud() as cloud:
            assert cloud._previous_timeout == original
            assert cloud_client._TIMEOUT_SECONDS == BENCHMARK_HTTP_TIMEOUT_SECONDS == 60
            assert cloud.timeout_overridden is True

    def test_restored_after_normal_exit(self):
        import client.cloud_client as cloud_client

        original = cloud_client._TIMEOUT_SECONDS
        with LiveCloud():
            pass
        assert cloud_client._TIMEOUT_SECONDS == original == 10

    def test_restored_after_an_exception_inside_the_context(self):
        """A failing benchmark must not leave the application module carrying a
        timeout it does not ship with."""
        import client.cloud_client as cloud_client

        original = cloud_client._TIMEOUT_SECONDS
        with pytest.raises(RuntimeError, match="simulated suite failure"):
            with LiveCloud():
                assert cloud_client._TIMEOUT_SECONDS == BENCHMARK_HTTP_TIMEOUT_SECONDS
                raise RuntimeError("simulated suite failure")
        assert cloud_client._TIMEOUT_SECONDS == original == 10

    def test_base_url_and_timeout_are_both_restored_together(self):
        import client.cloud_client as cloud_client

        url_before, timeout_before = cloud_client.CLOUD_BASE_URL, cloud_client._TIMEOUT_SECONDS
        with LiveCloud():
            pass
        assert cloud_client.CLOUD_BASE_URL == url_before
        assert cloud_client._TIMEOUT_SECONDS == timeout_before

    def test_metadata_states_the_deviation_explicitly(self):
        with LiveCloud() as cloud:
            meta = cloud.timeout_metadata()
        assert meta["shipped_timeout_seconds"] == 10
        assert meta["benchmark_timeout_seconds"] == 60
        assert meta["timeout_overridden"] is True
        assert meta["affects_measurements"] is False
        assert meta["retry_on_failure"] is False
        assert "benchmark-only" in meta["scope"]
        assert len(meta["rationale"]) > 100

    def test_b4_metadata_carries_the_timeout_deviation_into_the_manifest(self, b4_result):
        """The report has to be able to say 'the shipped client uses 10 s, the
        benchmark allowed 60 s' without a reader digging through the harness."""
        metadata, _ = b4_result
        http = metadata["http_timeout"]
        assert http["shipped_timeout_seconds"] == 10
        assert http["benchmark_timeout_seconds"] == 60
        assert http["timeout_overridden"] is True
        assert http["affects_measurements"] is False
        assert metadata["retry_policy"].startswith("none")

    def test_the_override_does_not_touch_the_application_source(self):
        """The override is a runtime attribute swap. The shipped module's own
        source must still declare 10 seconds."""
        import inspect

        import client.cloud_client as cloud_client

        source = inspect.getsource(cloud_client)
        assert "_TIMEOUT_SECONDS = 10" in source


class TestFailureDiagnostics:
    """Purely diagnostic, failure-path only. The B4 post-mortem could not
    distinguish a crashed cloud from a stalled one; this closes that gap."""

    def test_diagnostics_report_a_live_process(self):
        with LiveCloud() as cloud:
            info = cloud.diagnostics()
        assert info["process_started"] is True
        assert info["process_alive"] is True
        assert info["returncode"] is None
        assert info["http_timeout_in_effect_seconds"] == BENCHMARK_HTTP_TIMEOUT_SECONDS
        assert isinstance(info["captured_output_tail"], str)

    def test_diagnostics_report_a_dead_process(self):
        cloud = LiveCloud()
        cloud.__enter__()
        try:
            cloud.process.kill()
            cloud.process.wait(timeout=5)
            info = cloud.diagnostics()
            assert info["process_alive"] is False
            assert info["returncode"] is not None
        finally:
            cloud.__exit__(None, None, None)

    def test_a_failed_upload_attaches_process_state_and_output_tail(self, monkeypatch, tmp_path):
        """Simulate the shape of the authoritative failure: the cloud is
        unreachable from the client's point of view while the subprocess is
        still alive -- exactly the ambiguity the 2026-08-29 abort left behind."""
        from client import cloud_client

        calls = {"push": 0}

        def failing_push(*args, **kwargs):
            calls["push"] += 1
            raise cloud_client.CloudUnavailableError("simulated read timeout (read timeout=60)")

        monkeypatch.setattr(cloud_client, "push_document", failing_push)

        with pytest.raises(AssertionError) as excinfo:
            _run_suite(b4_upload_rebuild, tmp_path)

        message = str(excinfo.value)
        assert "B4 correctness gate failed" in message
        assert "one attempt, no retry" in message
        assert "cloud subprocess diagnostics" in message
        assert "process_alive" in message and "returncode" in message
        assert "captured_output_tail" in message
        assert "http_timeout_in_effect_seconds" in message

    def test_diagnostics_failing_on_the_upload_path_does_not_mask_the_real_error(
        self, monkeypatch, tmp_path
    ):
        """Found by the checkpoint-path work: if `diagnostics()` itself raises
        while reporting an upload failure, the diagnostic error would replace
        the real one and the actual cause would be lost."""
        from client import cloud_client

        def failing_push(*args, **kwargs):
            raise cloud_client.CloudUnavailableError("the real upload failure")

        monkeypatch.setattr(cloud_client, "push_document", failing_push)
        monkeypatch.setattr(LiveCloud, "diagnostics",
                            lambda self: (_ for _ in ()).throw(OSError("diagnostics broke")))
        with pytest.raises(AssertionError) as excinfo:
            _run_suite(b4_upload_rebuild, tmp_path)
        assert "the real upload failure" in str(excinfo.value)
        assert "diagnostics_failed" in str(excinfo.value)

    def test_a_failed_upload_is_attempted_exactly_once(self, monkeypatch, tmp_path):
        """No retry, no back-off, no second attempt: an upload is an n=1 state
        transition and re-issuing one would corrupt the measurement it is
        supposed to be."""
        from client import cloud_client

        calls = {"push": 0}

        def failing_push(*args, **kwargs):
            calls["push"] += 1
            raise cloud_client.CloudUnavailableError("simulated read timeout")

        monkeypatch.setattr(cloud_client, "push_document", failing_push)
        with pytest.raises(AssertionError):
            _run_suite(b4_upload_rebuild, tmp_path)
        assert calls["push"] == 1

    def test_diagnostics_are_not_collected_on_the_success_path(self, monkeypatch, tmp_path):
        """Diagnostics must never run inside a timed region. On a clean run the
        upload path must not call diagnostics() at all."""
        collected = {"n": 0}
        real_diagnostics = LiveCloud.diagnostics

        def counting_diagnostics(self):
            collected["n"] += 1
            return real_diagnostics(self)

        monkeypatch.setattr(LiveCloud, "diagnostics", counting_diagnostics)
        _run_suite(b4_upload_rebuild, tmp_path)
        assert collected["n"] == 0


class TestCheckpointPathDiagnostics:
    """Run 3 of the authoritative benchmark (2026-09-01) stalled inside the
    checkpoint block, not the upload loop, and produced a bare
    CloudUnavailableError with no diagnostics at all: 100 healthy uploads,
    92 minutes unaccounted, and nothing in the record about the server's
    state. These tests prove that path is now instrumented -- by breaking each
    operation on purpose and checking what the failure carries.
    """

    @staticmethod
    def _checkpoint_profile():
        """Tiny, but large enough to reach a checkpoint (uploads 1 and 2, with
        a checkpoint at 2) so the checkpoint code path actually executes."""
        return dataclasses.replace(
            TINY, upload_max_documents=2, rebuild_checkpoints=(2,), rebuild_repeats=1
        )

    @staticmethod
    def _stall_the_checkpoint_fetch(monkeypatch, counter=None):
        """Break `_fetch_all_documents`, which is called ONLY from the
        checkpoint block -- the exact place run 3 stalled, right after
        `rebuild_index_total` was recorded. `replace_index` and `build_index`
        would be the wrong targets: uploads use those too, so a fault there
        surfaces through the already-instrumented upload gate instead."""
        from client import cloud_client

        def stalled(*args, **kwargs):
            if counter is not None:
                counter["n"] += 1
            raise cloud_client.CloudUnavailableError(
                "simulated read timeout (read timeout=60)"
            )

        monkeypatch.setattr(b4_upload_rebuild, "_fetch_all_documents", stalled)

    def test_a_stalled_checkpoint_operation_reports_phase_and_process_state(
        self, monkeypatch, tmp_path
    ):
        self._stall_the_checkpoint_fetch(monkeypatch)
        with pytest.raises(b4_upload_rebuild.B4OperationError) as excinfo:
            _run_suite(b4_upload_rebuild, tmp_path, self._checkpoint_profile())

        message = str(excinfo.value)
        assert "B4 failed during" in message
        assert "checkpoint" in message, "the failing phase must be named"
        assert "attempted once, not retried" in message
        assert "cloud subprocess diagnostics" in message
        for field in ("process_alive", "returncode", "http_timeout_in_effect_seconds",
                      "captured_output_bytes", "captured_output_lines", "captured_output_tail"):
            assert field in message, f"{field} missing from the failure diagnostics"

    def test_the_original_exception_is_chained_not_swallowed(self, monkeypatch, tmp_path):
        from client import cloud_client

        self._stall_the_checkpoint_fetch(monkeypatch)
        with pytest.raises(b4_upload_rebuild.B4OperationError) as excinfo:
            _run_suite(b4_upload_rebuild, tmp_path, self._checkpoint_profile())
        cause = excinfo.value.__cause__
        assert isinstance(cause, cloud_client.CloudUnavailableError)
        assert "read timeout=60" in str(cause)

    def test_a_stalled_checkpoint_operation_is_attempted_exactly_once(
        self, monkeypatch, tmp_path
    ):
        counter = {"n": 0}
        self._stall_the_checkpoint_fetch(monkeypatch, counter)
        with pytest.raises(b4_upload_rebuild.B4OperationError):
            _run_suite(b4_upload_rebuild, tmp_path, self._checkpoint_profile())
        assert counter["n"] == 1, "the guard must not retry a failed operation"

    def test_diagnostics_failing_does_not_mask_the_real_error(self, monkeypatch, tmp_path):
        self._stall_the_checkpoint_fetch(monkeypatch)
        monkeypatch.setattr(LiveCloud, "diagnostics",
                            lambda self: (_ for _ in ()).throw(OSError("diagnostics broke")))
        with pytest.raises(b4_upload_rebuild.B4OperationError) as excinfo:
            _run_suite(b4_upload_rebuild, tmp_path, self._checkpoint_profile())
        assert "read timeout=60" in str(excinfo.value)
        assert "diagnostics_failed" in str(excinfo.value)

    def test_correctness_gates_still_raise_assertionerror_untouched(
        self, monkeypatch, tmp_path
    ):
        """The guard must not convert a correctness failure into a transport
        failure: a wrong measurement and a stalled server are different
        findings and must stay distinguishable."""
        real = b4_upload_rebuild.build_index
        monkeypatch.setattr(b4_upload_rebuild, "build_index",
                            lambda k, docs: real(k, docs)[:-1])
        with pytest.raises(AssertionError, match="postings"):
            _run_suite(b4_upload_rebuild, tmp_path, self._checkpoint_profile())

    def test_metadata_declares_the_instrumentation_and_the_no_retry_policy(self, b4_result):
        metadata, _ = b4_result
        fi = metadata["failure_instrumentation"]
        assert fi["retries_added"] is False
        assert fi["correctness_gates_unchanged"] is True
        assert "checkpoint" in fi["checkpoint_path"]
        for field in ("process_alive", "returncode", "http_timeout_in_effect_seconds",
                      "captured_output_tail"):
            assert field in fi["captured"]


class TestRawRowTimestamps:
    """Every raw row now carries wall-clock provenance, so a stall's start is
    readable directly from the raw file instead of being reconstructed by
    arithmetic against the manifest -- which is how the run 2 and run 3 gaps
    had to be located."""

    def test_every_row_carries_a_utc_timestamp_and_an_elapsed_offset(self, b4_result):
        import datetime as dt

        _, rows = b4_result
        assert rows
        for row in rows:
            assert "ts_utc" in row and "elapsed_since_run_start_s" in row
            parsed = dt.datetime.fromisoformat(row["ts_utc"])
            assert parsed.tzinfo is not None
            assert row["elapsed_since_run_start_s"] >= 0

    def test_timestamps_are_monotonic_in_write_order(self, b4_result):
        _, rows = b4_result
        offsets = [r["elapsed_since_run_start_s"] for r in rows]
        assert offsets == sorted(offsets)

    def test_gaps_between_consecutive_rows_are_directly_computable(self, b4_result):
        """This is the property the investigation needed and did not have."""
        _, rows = b4_result
        gaps = [b["elapsed_since_run_start_s"] - a["elapsed_since_run_start_s"]
                for a, b in zip(rows, rows[1:])]
        assert all(g >= 0 for g in gaps)
        assert max(gaps) < 600, "no single gap should be minutes long in a tiny self-test run"

    def test_timestamps_do_not_enter_any_statistic(self, b4_result):
        """Provenance only: the recorded `value` fields must be unchanged by the
        presence of timestamps."""
        _, rows = b4_result
        timed = [r for r in rows if r["unit"] == "s" and r["phase"] == "measure"]
        assert timed
        for row in timed:
            assert isinstance(row["value"], float)
            assert row["value"] < row["elapsed_since_run_start_s"] + 1.0


class TestWireCapture:
    def test_records_real_calls_and_restores_the_transport(self):
        from client import cloud_client

        with LiveCloud() as cloud:
            original = cloud_client.requests.request
            with record_wire(cloud.base_url) as wire:
                cloud_client.health()
                cloud_client.set_meta("probe", b"\x01\x02")
            assert cloud_client.requests.request is original
            assert wire.sequence == ["GET /health", "POST /meta/probe"]
            assert len(wire) == 2

    def test_summary_collapses_document_fetches_by_shape(self):
        from benchmarks.harness.wire import WireLog

        log = WireLog("http://x")
        log.add("GET", "http://x/documents/" + "a" * 32)
        log.add("GET", "http://x/documents/" + "b" * 32)
        log.add("POST", "http://x/search")
        assert log.summary() == {"GET /documents/<doc_id>": 2, "POST /search": 1}
        assert log.count("GET", r"/documents/[0-9a-f]+") == 2


# ---------------------------------------------------------------------------
# common contract
# ---------------------------------------------------------------------------

class TestCommonSuiteContract:
    @pytest.mark.parametrize("fixture_name", ["b4_result", "b5_result", "b6_result"])
    def test_every_declared_measure_produced_samples(self, fixture_name, request):
        """A suite may only declare what it actually recorded.

        The contract runs in that direction on purpose: `declared => present`,
        never `expected => must exist`. A measurement that depends on an
        optional platform capability (B6's per-table page accounting needs
        SQLite's `dbstat` virtual table, which the python.org Windows build
        does not ship) is therefore reported as unavailable and left out of
        `measures`, rather than being faked so a checklist passes.
        """
        metadata, rows = request.getfixturevalue(fixture_name)
        for name in metadata["measures"]:
            assert measured_values(rows, name) or scalar_values(rows, name), \
                f"{name} is declared but produced no recorded samples"

    @pytest.mark.parametrize("fixture_name", ["b4_result", "b5_result", "b6_result"])
    def test_unavailable_measures_are_declared_with_a_reason_and_absent_from_measures(
        self, fixture_name, request
    ):
        metadata, rows = request.getfixturevalue(fixture_name)
        for name, reason in metadata.get("unavailable_measures", {}).items():
            assert name not in metadata["measures"], (
                f"{name} cannot be both unavailable and declared as measured"
            )
            assert reason and len(reason) > 20, "an unavailable measure needs a stated reason"
            assert not measured_values(rows, name) and not scalar_values(rows, name), (
                f"{name} is declared unavailable but rows were recorded for it"
            )

    @pytest.mark.parametrize("fixture_name", ["b4_result", "b5_result", "b6_result"])
    def test_measures_the_shipped_implementation(self, fixture_name, request):
        metadata, _ = request.getfixturevalue(fixture_name)
        for dotted in metadata["implementations_under_test"]:
            assert dotted.startswith("client."), dotted

    @pytest.mark.parametrize("fixture_name", ["b4_result", "b5_result", "b6_result"])
    def test_correctness_gates_were_performed(self, fixture_name, request):
        metadata, _ = request.getfixturevalue(fixture_name)
        assert metadata["correctness_gates"]

    @pytest.mark.parametrize("fixture_name", ["b4_result", "b5_result"])
    def test_topology_is_the_real_two_process_split(self, fixture_name, request):
        metadata, _ = request.getfixturevalue(fixture_name)
        assert "subprocess" in metadata["topology"]


# ---------------------------------------------------------------------------
# B4
# ---------------------------------------------------------------------------

class TestB4UploadRebuild:
    def test_each_upload_is_a_single_observation(self, b4_result):
        """An upload is a state transition; claiming repeated samples for
        one would be a fabrication."""
        metadata, rows = b4_result
        assert metadata["per_upload_sample_size"] == 1
        for position in range(1, TINY.upload_max_documents + 1):
            values = measured_values(rows, "upload_document_end_to_end",
                                     {"vault_documents_after": position})
            assert len(values) == 1

    def test_document_fetches_per_upload_equal_the_vault_size(self, b4_result):
        """The static rebuild re-reads every stored document on every
        upload. This is the measured form of demonstration D7, and it is
        counted from real traffic rather than inferred."""
        _, rows = b4_result
        for position in range(1, TINY.upload_max_documents + 1):
            fetches = scalar_values(rows, "http_document_fetches_per_upload",
                                    {"vault_documents_after": position})
            assert fetches == [float(position)]

    def test_total_requests_per_upload_grow_with_the_vault(self, b4_result):
        _, rows = b4_result
        totals = [scalar_values(rows, "http_requests_per_upload",
                                {"vault_documents_after": p})[0]
                  for p in range(1, TINY.upload_max_documents + 1)]
        assert totals == sorted(totals) and totals[0] < totals[-1]

    def test_rebuild_is_measured_repeatedly_at_each_checkpoint(self, b4_result):
        _, rows = b4_result
        for checkpoint in TINY.rebuild_checkpoints:
            values = measured_values(rows, "rebuild_index_total",
                                     {"vault_documents": checkpoint})
            assert len(values) == TINY.rebuild_repeats

    def test_rebuild_decomposition_is_recorded_beside_the_whole(self, b4_result):
        _, rows = b4_result
        for checkpoint in TINY.rebuild_checkpoints:
            for step in ("rebuild_step_fetch_all_documents", "rebuild_step_decrypt_and_tokenize",
                         "rebuild_step_build_index", "rebuild_step_replace_index"):
                assert measured_values(rows, step, {"vault_documents": checkpoint})
            ratio = scalar_values(rows, "rebuild_decomposition_ratio",
                                  {"vault_documents": checkpoint})[0]
            assert 0.3 < ratio < 2.0, (
                f"decomposition sum is {ratio:.2f}x the measured whole -- the parts do "
                f"not account for the rebuild"
            )

    def test_postings_axis_is_recorded_for_scaling_analysis(self, b4_result):
        _, rows = b4_result
        for checkpoint in TINY.rebuild_checkpoints:
            postings = scalar_values(rows, "corpus_total_postings",
                                     {"vault_documents": checkpoint})
            assert postings and postings[0] > 0

    def test_a_broken_index_build_stops_the_suite(self, monkeypatch, tmp_path):
        real = b4_upload_rebuild.build_index
        monkeypatch.setattr(b4_upload_rebuild, "build_index",
                            lambda k, docs: real(k, docs)[:-1])
        with pytest.raises(AssertionError, match="postings"):
            _run_suite(b4_upload_rebuild, tmp_path)


# ---------------------------------------------------------------------------
# B5
# ---------------------------------------------------------------------------

class TestB5Search:
    def test_both_boundaries_measured_for_every_match_count(self, b5_result):
        _, rows = b5_result
        for k in TINY.search_match_counts:
            assert len(measured_values(rows, "cloud_search_loop",
                                       {"matching_documents": k})) == TINY.search_repeats
            assert len(measured_values(rows, "client_search_end_to_end",
                                       {"matching_documents": k})) == TINY.search_repeats

    def test_result_counts_match_the_planted_probe_frequencies(self, b5_result):
        _, rows = b5_result
        for k in TINY.search_match_counts:
            assert scalar_values(rows, "search_result_count",
                                 {"matching_documents": k}) == [float(k)]

    def test_observed_document_fetches_equal_the_result_count(self, b5_result):
        """Audit M4 / demonstration D3b, as a measurement: the client fetches
        one document per result, naming each matched handle to the cloud."""
        _, rows = b5_result
        for k in TINY.search_match_counts:
            assert scalar_values(rows, "search_document_fetches",
                                 {"matching_documents": k}) == [float(k)]

    def test_access_pattern_is_captured_from_real_traffic(self, b5_result):
        metadata, _ = b5_result
        row = metadata["experiment_match_count_scaling"]["results"][0]
        assert row["access_pattern"][0] == "POST /search"
        assert "GET /documents/<doc_id>" in row["access_pattern_shape"]

    def test_eager_fetch_cost_is_recorded_per_match_count(self, b5_result):
        _, rows = b5_result
        for k in TINY.search_match_counts:
            values = scalar_values(rows, "eager_fetch_cost_seconds", {"matching_documents": k})
            assert values and values[0] >= 0

    def test_index_size_experiment_holds_the_result_count_fixed(self, b5_result):
        metadata, rows = b5_result
        scaling = metadata["experiment_index_size_scaling"]
        assert scaling["fixed_result_count"] == TINY.search_scaling_fixed_k
        assert scaling["results"]
        assert measured_values(rows, "cloud_search_loop_fixed_k")
        assert all(r["matching_documents"] == TINY.search_scaling_fixed_k for r in scaling["results"])

    def test_a_search_returning_the_wrong_documents_stops_the_suite(self, monkeypatch, tmp_path):
        monkeypatch.setattr(b5_search, "probe_keyword", lambda k: "notaplantedkeyword")
        with pytest.raises(AssertionError, match="ground truth"):
            _run_suite(b5_search, tmp_path)


# ---------------------------------------------------------------------------
# B6
# ---------------------------------------------------------------------------

class TestB6Storage:
    def test_database_size_is_read_from_the_filesystem(self, b6_result):
        _, rows = b6_result
        db_bytes = scalar_values(rows, "database_file_bytes", {"documents": 4})[0]
        pages = scalar_values(rows, "database_pages_bytes", {"documents": 4})[0]
        assert db_bytes > 0 and pages > 0

    def test_no_estimates_are_used(self, b6_result):
        metadata, _ = b6_result
        assert metadata["measurement_method"]["estimates_used"] is False
        assert "getsize" in metadata["measurement_method"]["file_bytes"]

    def test_per_table_accounting_matches_the_recorded_capability(self, b6_result):
        """`dbstat` is a SQLite compile-time option. Whichever way it goes, the
        recorded capability flag, the declared measures and the rows on disk
        must agree -- that agreement is what lets the report distinguish a
        measured per-table figure from a build where none exists."""
        metadata, rows = b6_result
        available = bool(scalar_values(rows, "dbstat_available", {"documents": 4})[0])
        assert metadata["capabilities"]["dbstat"] is available
        btrees = {r["params"]["btree"] for r in rows if r["benchmark"] == "table_page_bytes"}
        if available:
            assert {"documents", "sse_index"} <= btrees
            assert "table_page_bytes" in metadata["measures"]
            assert "table_page_bytes" not in metadata.get("unavailable_measures", {})
            assert "dbstat" in metadata["measurement_method"]["per_table_bytes"]
        else:
            assert not btrees
            assert "table_page_bytes" not in metadata["measures"]
            assert "table_page_bytes" in metadata["unavailable_measures"]
            assert metadata["measurement_method"]["per_table_bytes"].startswith("UNAVAILABLE")

    def test_without_dbstat_the_suite_degrades_and_says_so(self, monkeypatch, tmp_path):
        """The reference environment (Windows 11, python.org CPython) has no
        `dbstat`. Simulating its absence here proves the fallback path is
        honest: the suite still runs, still records every filesystem and
        logical measurement, records the capability as false, and does NOT
        relabel logical column sums as per-table page bytes.
        """
        monkeypatch.setattr(b6_storage, "_dbstat_pages", lambda conn: {})
        metadata, rows = _run_suite(b6_storage, tmp_path)

        assert metadata["capabilities"]["dbstat"] is False
        assert scalar_values(rows, "dbstat_available", {"documents": 4}) == [0.0]
        assert "table_page_bytes" not in metadata["measures"]
        assert not [r for r in rows if r["benchmark"] == "table_page_bytes"]

        reason = metadata["unavailable_measures"]["table_page_bytes"]
        assert "dbstat" in reason and "not a substitute" in reason

        # Every measurement that does not depend on dbstat is still present,
        # so losing an optional capability costs exactly one measurement.
        for name in ("database_file_bytes", "database_pages_bytes", "plaintext_corpus_bytes",
                     "documents_ciphertext_bytes", "index_label_bytes", "index_value_bytes"):
            assert scalar_values(rows, name, {"documents": 4}), f"{name} lost with dbstat"
        assert metadata["measurement_method"]["estimates_used"] is False

    def test_logical_sums_are_never_relabelled_as_page_bytes(self, monkeypatch, tmp_path):
        """The specific dishonesty this guards against: making the contract
        pass by writing the logical column sum out under the page-bytes name.
        The two answer different questions -- payload bytes versus B-tree page
        usage -- and page usage is strictly larger."""
        monkeypatch.setattr(b6_storage, "_dbstat_pages", lambda conn: {})
        _, rows = _run_suite(b6_storage, tmp_path)
        recorded = {r["benchmark"] for r in rows}
        assert "table_page_bytes" not in recorded
        assert {"index_label_bytes", "index_value_bytes"} <= recorded

    def test_row_counts_match_the_corpus(self, b6_result):
        _, rows = b6_result
        docs = scalar_values(rows, "documents_rows", {"documents": 4})[0]
        index_rows = scalar_values(rows, "sse_index_rows", {"documents": 4})[0]
        postings = scalar_values(rows, "total_postings", {"documents": 4})[0]
        assert docs == 4.0
        assert index_rows == postings

    def test_ciphertext_bytes_equal_plaintext_bytes_for_gcm(self, b6_result):
        """AES-GCM is a stream cipher mode: the ciphertext is the same length
        as the plaintext, and the 28 bytes of nonce and tag are stored
        separately. Measuring that rather than assuming it is what makes the
        overhead figure defensible."""
        _, rows = b6_result
        plaintext = scalar_values(rows, "plaintext_corpus_bytes", {"documents": 4})[0]
        ciphertext = scalar_values(rows, "documents_ciphertext_bytes", {"documents": 4})[0]
        nonce_tag = scalar_values(rows, "documents_nonce_and_tag_bytes", {"documents": 4})[0]
        assert ciphertext == plaintext
        assert nonce_tag == 28 * 4

    def test_index_storage_is_measured_separately_from_documents(self, b6_result):
        _, rows = b6_result
        assert scalar_values(rows, "index_label_bytes", {"documents": 4})[0] > 0
        assert scalar_values(rows, "index_value_bytes", {"documents": 4})[0] > 0

    def test_a_short_vault_stops_the_suite(self, monkeypatch, tmp_path):
        real = b6_storage.populate_vault
        monkeypatch.setattr(b6_storage, "populate_vault",
                            lambda keys, docs: real(keys, docs[:-1]))
        with pytest.raises(AssertionError, match="documents"):
            _run_suite(b6_storage, tmp_path)
