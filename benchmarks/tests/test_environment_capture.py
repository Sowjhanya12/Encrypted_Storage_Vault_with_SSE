"""
Self-tests for benchmarks/harness/environment.py.

Two things are worth testing about an environment record: that it
contains what a reader needs to reproduce a number, and that it does
not contain anything about the person who ran it.
"""

import getpass
import socket

from benchmarks.harness.environment import capture, one_line_summary


class TestEnvironmentRecordCompleteness:
    def test_records_the_fields_the_report_depends_on(self):
        env = capture()
        for key in (
            "captured_at_utc", "platform", "machine", "python_version",
            "python_implementation", "sqlite_version", "libraries",
            "hardware", "argon2_production_parameters", "timer",
        ):
            assert key in env, f"missing environment field: {key}"

    def test_tracks_the_libraries_that_can_change_a_measurement(self):
        libs = capture()["libraries"]
        for name in ("cryptography", "argon2", "flask", "requests"):
            assert name in libs, f"{name} version is not tracked"

    def test_missing_optional_library_records_none_rather_than_failing(self):
        libs = capture()["libraries"]
        assert all(v is None or isinstance(v, str) for v in libs.values())

    def test_timer_resolution_is_measured_not_assumed(self):
        timer = capture()["timer"]
        assert timer["clock"] == "time.perf_counter_ns"
        assert 0 < timer["resolution_seconds"] < 1e-3

    def test_argon2_production_parameters_come_from_the_application(self):
        """These must be read from client/keymgmt.py, not restated in
        the harness -- a benchmark that reports parameters the
        application does not actually use is worse than no benchmark."""
        from client import keymgmt

        params = capture()["argon2_production_parameters"]
        assert params["available"] is True
        assert params["time_cost"] == keymgmt.ARGON2_TIME_COST
        assert params["memory_cost_kib"] == keymgmt.ARGON2_MEMORY_COST_KIB
        assert params["parallelism"] == keymgmt.ARGON2_PARALLELISM

    def test_records_that_argon2_parameters_are_not_persisted_in_the_vault(self):
        """Audit finding M1, still open at Phase 7: the vault stores no
        record of the parameters that derived its keys."""
        assert capture()["argon2_production_parameters"]["persisted_in_vault_meta"] is False

    def test_hardware_block_degrades_without_psutil(self):
        hw = capture()["hardware"]
        assert "logical_cores" in hw and "psutil_available" in hw
        if not hw["psutil_available"]:
            assert hw["total_ram_bytes"] is None


class TestEnvironmentRecordPrivacy:
    def test_does_not_contain_the_hostname_or_username(self):
        blob = repr(capture())
        for identifier in (socket.gethostname(), getpass.getuser()):
            if identifier and len(identifier) > 2:
                assert identifier not in blob, (
                    "the environment record must describe the machine's shape, "
                    "not identify its owner"
                )

    def test_summary_line_is_human_readable(self):
        line = one_line_summary(capture())
        assert "Python" in line and "core" in line
