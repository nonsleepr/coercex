"""Tests for the Rich Live scan display."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.progress import Progress
from rich.text import Text

from coercex.cli.display import ScanDisplay, _TargetProgress
from coercex.models import ScanResult, TriggerResult


# -- Helpers -----------------------------------------------------------------


def _make_console() -> Console:
    """Create a non-interactive console that writes to a string buffer."""
    return Console(file=StringIO(), force_terminal=True, width=120)


def _make_display(
    targets: list[str] | None = None,
    *,
    verbose: bool = False,
) -> ScanDisplay:
    targets = targets or ["10.0.0.1"]
    return ScanDisplay(_make_console(), targets, verbose=verbose)


def _make_result(
    target: str = "10.0.0.1",
    result: TriggerResult = TriggerResult.NOT_AVAILABLE,
    protocol: str = "MS-EFSR",
    method: str = "EfsRpcOpenFileRaw",
    pipe: str = r"\pipe\efsrpc",
    uuid: str = "c681d488-d850-11d0-8c52-00c04fd90f7e",
    transport: str = "smb",
    auth_user: str = "",
    ntlmv2_hash: str = "",
) -> ScanResult:
    return ScanResult(
        target=target,
        protocol=protocol,
        method=method,
        pipe=pipe,
        uuid=uuid,
        result=result,
        transport=transport,
        auth_user=auth_user,
        ntlmv2_hash=ntlmv2_hash,
    )


# -- _TargetProgress ---------------------------------------------------------


class TestTargetProgress:
    def test_defaults(self) -> None:
        tp = _TargetProgress()
        assert tp.total == 0
        assert tp.completed == 0
        assert tp.vulnerable == 0
        assert tp.accessible == 0
        assert tp.sent == 0
        assert tp.access_denied == 0
        assert tp.not_available == 0
        assert tp.connect_errors == 0
        assert tp.timeouts == 0
        assert tp.unknown_errors == 0


# -- Phase transitions -------------------------------------------------------


class TestPhaseTransitions:
    def test_initial_phase_is_init(self) -> None:
        d = _make_display()
        assert d._phase == "init"

    def test_start_probe_sets_phase(self) -> None:
        d = _make_display()
        d.start_probe(12)
        assert d._phase == "probe"
        assert d._probe_task_id is not None

    def test_finish_probe_transitions_to_scan(self) -> None:
        d = _make_display()
        d.start_probe(5)
        d.advance_probe(3)
        d.finish_probe()
        assert d._phase == "scan"

    def test_finish_probe_with_reachable_info(self) -> None:
        d = _make_display(["10.0.0.1", "10.0.0.2"])
        d.start_probe(10)
        d.advance_probe(10)
        d.finish_probe(
            reachable={"10.0.0.1": 9, "10.0.0.2": 0},
            total_bindings=11,
        )
        assert d._phase == "scan"

    def test_start_drain_sets_phase(self) -> None:
        d = _make_display()
        d.start_probe(1)
        d.finish_probe()
        d.start_drain()
        assert d._phase == "drain"

    def test_finish_drain_sets_done_phase(self) -> None:
        d = _make_display()
        d.start_probe(1)
        d.finish_probe()
        d.start_drain()
        d.finish_drain()
        assert d._phase == "done"

    def test_advance_probe_without_start_is_noop(self) -> None:
        d = _make_display()
        # Should not raise
        d.advance_probe(5)


# -- Layout building ---------------------------------------------------------


class TestBuildLayout:
    def test_init_phase_shows_initializing(self) -> None:
        d = _make_display()
        layout = d._build_layout()
        # Group contains renderables — last one is Text "Initializing…"
        renderables = list(layout.renderables)
        assert any(
            isinstance(r, Text) and "Initializing" in str(r) for r in renderables
        )

    def test_probe_phase_shows_probe_progress(self) -> None:
        d = _make_display()
        d.start_probe(10)
        layout = d._build_layout()
        renderables = list(layout.renderables)
        assert any(isinstance(r, Progress) for r in renderables)

    def test_scan_phase_shows_scan_progress(self) -> None:
        d = _make_display()
        d._phase = "scan"
        layout = d._build_layout()
        renderables = list(layout.renderables)
        assert any(isinstance(r, Progress) for r in renderables)

    def test_drain_phase_shows_waiting_text(self) -> None:
        d = _make_display()
        d._phase = "drain"
        layout = d._build_layout()
        renderables = list(layout.renderables)
        assert any(
            isinstance(r, Text) and "Waiting for late callbacks" in str(r)
            for r in renderables
        )

    def test_done_phase_shows_progress_without_waiting(self) -> None:
        d = _make_display()
        d._phase = "done"
        layout = d._build_layout()
        renderables = list(layout.renderables)
        assert any(isinstance(r, Progress) for r in renderables)
        assert not any(isinstance(r, Text) and "Waiting" in str(r) for r in renderables)

    def test_no_results_table_when_empty(self) -> None:
        d = _make_display()
        table = d._build_results_table()
        assert table is None

    def test_results_table_built_when_interesting(self) -> None:
        d = _make_display()
        d.set_target_total("10.0.0.1", 5)
        d.add_result(_make_result(result=TriggerResult.VULNERABLE))
        table = d._build_results_table()
        assert table is not None
        assert table.row_count == 1


# -- set_target_total --------------------------------------------------------


class TestSetTargetTotal:
    def test_sets_total_on_target(self) -> None:
        d = _make_display()
        d.set_target_total("10.0.0.1", 20)
        assert d._target_progress["10.0.0.1"].total == 20

    def test_zero_total_marks_no_reachable(self) -> None:
        d = _make_display()
        d.set_target_total("10.0.0.1", 0)
        task = d._scan_progress.tasks[0]
        assert "no reachable" in task.fields["status"]

    def test_unknown_target_no_crash(self) -> None:
        d = _make_display()
        # Should not raise
        d.set_target_total("unknown.host", 10)


# -- mark_target_done --------------------------------------------------------


class TestMarkTargetDone:
    def test_marks_target_complete(self) -> None:
        d = _make_display(["10.0.0.1"])
        d.set_target_total("10.0.0.1", 10)
        d.mark_target_done("10.0.0.1", reason="vulnerable found")
        task = d._scan_progress.tasks[0]
        assert "vulnerable found" in task.fields["status"]

    def test_unknown_target_no_crash(self) -> None:
        d = _make_display()
        d.mark_target_done("unknown.host")


# -- add_result --------------------------------------------------------------


class TestAddResult:
    def test_increments_completed(self) -> None:
        d = _make_display()
        d.set_target_total("10.0.0.1", 10)
        d.add_result(_make_result(result=TriggerResult.NOT_AVAILABLE))
        assert d._target_progress["10.0.0.1"].completed == 1

    def test_increments_correct_counter(self) -> None:
        d = _make_display()
        d.set_target_total("10.0.0.1", 10)

        counter_map = {
            TriggerResult.VULNERABLE: "vulnerable",
            TriggerResult.ACCESSIBLE: "accessible",
            TriggerResult.SENT: "sent",
            TriggerResult.ACCESS_DENIED: "access_denied",
            TriggerResult.NOT_AVAILABLE: "not_available",
            TriggerResult.CONNECT_ERROR: "connect_errors",
            TriggerResult.TIMEOUT: "timeouts",
            TriggerResult.UNKNOWN_ERROR: "unknown_errors",
        }

        for status, attr in counter_map.items():
            d2 = _make_display()
            d2.set_target_total("10.0.0.1", 10)
            d2.add_result(_make_result(result=status))
            tp = d2._target_progress["10.0.0.1"]
            assert getattr(tp, attr) == 1, f"{status} should increment {attr}"
            assert tp.completed == 1

    def test_interesting_results_collected(self) -> None:
        d = _make_display()
        d.set_target_total("10.0.0.1", 20)

        # VULNERABLE, ACCESSIBLE, SENT are interesting
        d.add_result(_make_result(result=TriggerResult.VULNERABLE, method="M1"))
        d.add_result(_make_result(result=TriggerResult.ACCESSIBLE, method="M2"))
        d.add_result(_make_result(result=TriggerResult.SENT, method="M3"))
        assert len(d._interesting_results) == 3

        # Non-interesting results
        d.add_result(_make_result(result=TriggerResult.ACCESS_DENIED, method="M4"))
        d.add_result(_make_result(result=TriggerResult.NOT_AVAILABLE, method="M5"))
        d.add_result(_make_result(result=TriggerResult.CONNECT_ERROR, method="M6"))
        d.add_result(_make_result(result=TriggerResult.TIMEOUT, method="M7"))
        d.add_result(_make_result(result=TriggerResult.UNKNOWN_ERROR, method="M8"))
        assert len(d._interesting_results) == 3  # unchanged

    def test_multiple_targets(self) -> None:
        targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        d = _make_display(targets)
        for t in targets:
            d.set_target_total(t, 5)

        d.add_result(_make_result(target="10.0.0.1", result=TriggerResult.VULNERABLE))
        d.add_result(
            _make_result(target="10.0.0.2", result=TriggerResult.ACCESS_DENIED)
        )
        d.add_result(
            _make_result(target="10.0.0.3", result=TriggerResult.NOT_AVAILABLE)
        )

        assert d._target_progress["10.0.0.1"].vulnerable == 1
        assert d._target_progress["10.0.0.2"].access_denied == 1
        assert d._target_progress["10.0.0.3"].not_available == 1

        for t in targets:
            assert d._target_progress[t].completed == 1


# -- result_upgraded ---------------------------------------------------------


class TestResultUpgraded:
    def test_counters_adjusted_on_upgrade(self) -> None:
        d = _make_display()
        d.set_target_total("10.0.0.1", 10)

        # First: add as ACCESSIBLE
        result = _make_result(result=TriggerResult.ACCESSIBLE)
        d.add_result(result)

        tp = d._target_progress["10.0.0.1"]
        assert tp.accessible == 1
        assert tp.vulnerable == 0
        assert tp.completed == 1

        # Upgrade to VULNERABLE
        result.result = TriggerResult.VULNERABLE
        d.result_upgraded(result, old_status=TriggerResult.ACCESSIBLE)

        assert tp.accessible == 0
        assert tp.vulnerable == 1
        # completed should NOT change (result_upgraded doesn't touch it)
        assert tp.completed == 1

    def test_upgrade_adds_to_interesting_if_newly_eligible(self) -> None:
        d = _make_display()
        d.set_target_total("10.0.0.1", 10)

        # Add as UNKNOWN_ERROR (not interesting)
        result = _make_result(result=TriggerResult.UNKNOWN_ERROR)
        d.add_result(result)
        assert len(d._interesting_results) == 0

        # Upgrade to VULNERABLE (interesting)
        result.result = TriggerResult.VULNERABLE
        d.result_upgraded(result, old_status=TriggerResult.UNKNOWN_ERROR)
        assert len(d._interesting_results) == 1
        assert d._interesting_results[0] is result

    def test_upgrade_does_not_duplicate_if_already_interesting(self) -> None:
        d = _make_display()
        d.set_target_total("10.0.0.1", 10)

        # ACCESSIBLE is already interesting
        result = _make_result(result=TriggerResult.ACCESSIBLE)
        d.add_result(result)
        assert len(d._interesting_results) == 1

        # Upgrade ACCESSIBLE → VULNERABLE (both interesting)
        result.result = TriggerResult.VULNERABLE
        d.result_upgraded(result, old_status=TriggerResult.ACCESSIBLE)
        # Should NOT add a duplicate entry
        assert len(d._interesting_results) == 1

    def test_upgrade_unknown_target_no_crash(self) -> None:
        d = _make_display()
        result = _make_result(target="unknown.host", result=TriggerResult.VULNERABLE)
        d.result_upgraded(result, old_status=TriggerResult.ACCESSIBLE)


# -- Counter helpers ---------------------------------------------------------


class TestCounterHelpers:
    def test_increment_all_statuses(self) -> None:
        tp = _TargetProgress()
        ScanDisplay._increment_counter(tp, TriggerResult.VULNERABLE)
        ScanDisplay._increment_counter(tp, TriggerResult.ACCESSIBLE)
        ScanDisplay._increment_counter(tp, TriggerResult.SENT)
        ScanDisplay._increment_counter(tp, TriggerResult.ACCESS_DENIED)
        ScanDisplay._increment_counter(tp, TriggerResult.NOT_AVAILABLE)
        ScanDisplay._increment_counter(tp, TriggerResult.CONNECT_ERROR)
        ScanDisplay._increment_counter(tp, TriggerResult.TIMEOUT)
        ScanDisplay._increment_counter(tp, TriggerResult.UNKNOWN_ERROR)

        assert tp.vulnerable == 1
        assert tp.accessible == 1
        assert tp.sent == 1
        assert tp.access_denied == 1
        assert tp.not_available == 1
        assert tp.connect_errors == 1
        assert tp.timeouts == 1
        assert tp.unknown_errors == 1

    def test_decrement_all_statuses(self) -> None:
        tp = _TargetProgress(
            vulnerable=2,
            accessible=2,
            sent=2,
            access_denied=2,
            not_available=2,
            connect_errors=2,
            timeouts=2,
            unknown_errors=2,
        )
        ScanDisplay._decrement_counter(tp, TriggerResult.VULNERABLE)
        ScanDisplay._decrement_counter(tp, TriggerResult.ACCESSIBLE)
        ScanDisplay._decrement_counter(tp, TriggerResult.SENT)
        ScanDisplay._decrement_counter(tp, TriggerResult.ACCESS_DENIED)
        ScanDisplay._decrement_counter(tp, TriggerResult.NOT_AVAILABLE)
        ScanDisplay._decrement_counter(tp, TriggerResult.CONNECT_ERROR)
        ScanDisplay._decrement_counter(tp, TriggerResult.TIMEOUT)
        ScanDisplay._decrement_counter(tp, TriggerResult.UNKNOWN_ERROR)

        assert tp.vulnerable == 1
        assert tp.accessible == 1
        assert tp.sent == 1
        assert tp.access_denied == 1
        assert tp.not_available == 1
        assert tp.connect_errors == 1
        assert tp.timeouts == 1
        assert tp.unknown_errors == 1


# -- _format_counters --------------------------------------------------------


class TestFormatCounters:
    def test_empty_counters_show_ellipsis(self) -> None:
        d = _make_display()
        tp = _TargetProgress()
        text = d._format_counters(tp)
        assert text == "[dim]...[/]"

    def test_shows_all_nonzero_counters(self) -> None:
        d = _make_display()
        tp = _TargetProgress(
            vulnerable=2,
            accessible=1,
            sent=3,
            access_denied=4,
            not_available=5,
            connect_errors=1,
            timeouts=2,
            unknown_errors=1,
        )
        text = d._format_counters(tp)
        assert "2 vuln" in text
        assert "1 acc" in text
        assert "3 sent" in text
        assert "4 denied" in text
        assert "5 n/a" in text
        assert "1 err" in text
        assert "2 tmout" in text
        assert "1 unk" in text

    def test_only_shows_nonzero(self) -> None:
        d = _make_display()
        tp = _TargetProgress(vulnerable=1, not_available=3)
        text = d._format_counters(tp)
        assert "vuln" in text
        assert "n/a" in text
        assert "acc" not in text
        assert "sent" not in text
        assert "denied" not in text
        assert "err" not in text
        assert "tmout" not in text
        assert "unk" not in text


# -- Lifecycle ---------------------------------------------------------------


class TestLifecycle:
    def test_start_and_stop(self) -> None:
        d = _make_display()
        d.start()
        assert d._live is not None
        d.stop()
        assert d._live is None

    def test_stop_without_start(self) -> None:
        d = _make_display()
        # Should not raise
        d.stop()

    def test_double_stop(self) -> None:
        d = _make_display()
        d.start()
        d.stop()
        d.stop()  # Should not raise


# -- Multi-target display initialization -------------------------------------


class TestMultiTarget:
    def test_creates_tasks_for_each_target(self) -> None:
        targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        d = _make_display(targets)
        assert len(d._scan_task_ids) == 3
        assert len(d._scan_progress.tasks) == 3

    def test_target_progress_initialized(self) -> None:
        targets = ["host-a", "host-b"]
        d = _make_display(targets)
        for t in targets:
            assert t in d._target_progress
            assert d._target_progress[t].total == 0


# -- End-to-end flow ---------------------------------------------------------


class TestEndToEndFlow:
    """Simulates a realistic scan lifecycle through the display."""

    def test_full_scan_lifecycle(self) -> None:
        targets = ["10.0.0.1", "10.0.0.2"]
        d = _make_display(targets)

        # 1. Start
        d.start()

        # 2. Probe phase
        d.start_probe(6)
        assert d._phase == "probe"
        for _ in range(6):
            d.advance_probe()
        d.finish_probe()
        assert d._phase == "scan"

        # 3. Set target totals
        d.set_target_total("10.0.0.1", 5)
        d.set_target_total("10.0.0.2", 3)

        # 4. Add results for target 1
        d.add_result(
            _make_result(target="10.0.0.1", result=TriggerResult.NOT_AVAILABLE)
        )
        d.add_result(
            _make_result(target="10.0.0.1", result=TriggerResult.ACCESS_DENIED)
        )
        d.add_result(
            _make_result(
                target="10.0.0.1",
                result=TriggerResult.VULNERABLE,
                method="EfsRpcOpenFileRaw",
            )
        )
        d.add_result(
            _make_result(target="10.0.0.1", result=TriggerResult.NOT_AVAILABLE)
        )
        d.add_result(
            _make_result(target="10.0.0.1", result=TriggerResult.NOT_AVAILABLE)
        )

        tp1 = d._target_progress["10.0.0.1"]
        assert tp1.completed == 5
        assert tp1.vulnerable == 1
        assert tp1.access_denied == 1
        assert tp1.not_available == 3

        # 5. Add results for target 2
        d.add_result(_make_result(target="10.0.0.2", result=TriggerResult.ACCESSIBLE))
        d.add_result(
            _make_result(target="10.0.0.2", result=TriggerResult.NOT_AVAILABLE)
        )
        d.add_result(_make_result(target="10.0.0.2", result=TriggerResult.TIMEOUT))

        tp2 = d._target_progress["10.0.0.2"]
        assert tp2.completed == 3
        assert tp2.accessible == 1
        assert tp2.not_available == 1
        assert tp2.timeouts == 1

        # Findings table should have VULNERABLE + ACCESSIBLE = 2 rows
        assert len(d._interesting_results) == 2

        # 6. Drain phase with an upgrade
        d.start_drain()
        assert d._phase == "drain"

        # Simulate late callback upgrading ACCESSIBLE → VULNERABLE
        accessible_result = d._interesting_results[1]  # The ACCESSIBLE one
        accessible_result.result = TriggerResult.VULNERABLE
        d.result_upgraded(accessible_result, old_status=TriggerResult.ACCESSIBLE)

        assert tp2.accessible == 0
        assert tp2.vulnerable == 1

        # Still 2 interesting results (the object was mutated in place)
        assert len(d._interesting_results) == 2

        # 7. Finish drain — removes "Waiting…" text
        d.finish_drain()
        assert d._phase == "done"

        # 8. Stop
        d.stop()
        assert d._live is None


# -- Results table rendering -------------------------------------------------


class TestResultsTable:
    def test_table_columns(self) -> None:
        d = _make_display()
        d.set_target_total("10.0.0.1", 5)
        d.add_result(
            _make_result(
                result=TriggerResult.VULNERABLE,
                auth_user=r"CORP\admin",
                ntlmv2_hash="admin::CORP:abc:def:1234",
            )
        )
        table = d._build_results_table()
        assert table is not None
        assert len(table.columns) == 7
        column_names = [str(c.header) for c in table.columns]
        assert "Target" in column_names
        assert "Protocol" in column_names
        assert "Method" in column_names
        assert "Auth User" in column_names

    def test_table_grows_with_results(self) -> None:
        d = _make_display()
        d.set_target_total("10.0.0.1", 10)

        d.add_result(_make_result(result=TriggerResult.SENT, method="M1"))
        assert d._build_results_table().row_count == 1  # type: ignore[union-attr]

        d.add_result(_make_result(result=TriggerResult.ACCESSIBLE, method="M2"))
        assert d._build_results_table().row_count == 2  # type: ignore[union-attr]

        d.add_result(_make_result(result=TriggerResult.VULNERABLE, method="M3"))
        assert d._build_results_table().row_count == 3  # type: ignore[union-attr]

        # Non-interesting result shouldn't add a row
        d.add_result(_make_result(result=TriggerResult.NOT_AVAILABLE, method="M4"))
        assert d._build_results_table().row_count == 3  # type: ignore[union-attr]
