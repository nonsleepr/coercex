"""Tests for method registry: loading, filtering, grouping."""

from __future__ import annotations

from coercex.methods import (
    ALL_PROTOCOLS,
    get_all_methods,
    group_by_pipe,
    _matches_any_pattern,
)


# -- _matches_any_pattern -----------------------------------------------------


class TestMatchesAnyPattern:
    """Test glob/regex/exact pattern matching."""

    def test_exact_match_case_insensitive(self):
        assert _matches_any_pattern("EfsRpcOpenFileRaw", ["efsrpcopenfileraw"])

    def test_exact_match_no_partial(self):
        assert not _matches_any_pattern("EfsRpcOpenFileRaw", ["EfsRpc"])

    def test_glob_star(self):
        assert _matches_any_pattern("EfsRpcOpenFileRaw", ["EfsRpc*"])

    def test_glob_question(self):
        assert _matches_any_pattern("abc", ["a?c"])

    def test_glob_no_match(self):
        assert not _matches_any_pattern("NetrDfsAddStdRoot", ["EfsRpc*"])

    def test_regex_dot_star(self):
        assert _matches_any_pattern("EfsRpcOpenFileRaw", ["EfsRpc.*Raw"])

    def test_regex_alternation(self):
        assert _matches_any_pattern("EfsRpcOpenFileRaw", ["EfsRpc.*|NetrDfs.*"])

    def test_regex_no_match(self):
        assert not _matches_any_pattern("IsPathSupported", ["EfsRpc.*"])

    def test_multiple_patterns(self):
        assert _matches_any_pattern("IsPathSupported", ["EfsRpc*", "IsPath*"])

    def test_empty_patterns(self):
        assert not _matches_any_pattern("anything", [])


# -- get_all_methods ----------------------------------------------------------


class TestGetAllMethods:
    """Test method loading and filtering."""

    def test_loads_all_methods(self):
        methods = get_all_methods()
        assert len(methods) >= 19

    def test_all_methods_have_trigger_fn(self):
        for m in get_all_methods():
            assert m.trigger_fn is not None, f"{m} has no trigger_fn"

    def test_all_methods_have_pipe_bindings(self):
        for m in get_all_methods():
            assert len(m.pipe_bindings) > 0, f"{m} has no pipe_bindings"

    def test_all_methods_have_path_styles(self):
        for m in get_all_methods():
            assert len(m.path_styles) > 0, f"{m} has no path_styles"

    def test_filter_by_protocol(self):
        methods = get_all_methods(protocols=["MS-RPRN"])
        assert all(m.protocol_short == "MS-RPRN" for m in methods)
        assert len(methods) == 2

    def test_filter_by_method_name_glob(self):
        methods = get_all_methods(methods_filter=["EfsRpc*"])
        assert all("EfsRpc" in m.function_name for m in methods)
        assert len(methods) == 10

    def test_filter_by_pipe(self):
        methods = get_all_methods(pipes_filter=[r"\PIPE\spoolss"])
        for m in methods:
            pipes = [b.pipe for b in m.pipe_bindings]
            assert r"\PIPE\spoolss" in pipes

    def test_filter_returns_empty_for_nonexistent(self):
        methods = get_all_methods(protocols=["MS-NONEXISTENT"])
        assert methods == []

    def test_all_protocols_covered(self):
        methods = get_all_methods()
        found_protocols = {m.protocol_short for m in methods}
        assert found_protocols == set(ALL_PROTOCOLS)


# -- group_by_pipe ------------------------------------------------------------


class TestGroupByPipe:
    def test_groups_by_pipe_uuid_version(self):
        methods = get_all_methods()
        groups = group_by_pipe(methods)
        assert len(groups) > 0
        for (pipe, uuid, version), group_methods in groups.items():
            assert pipe.startswith("\\PIPE\\")
            assert len(uuid) > 0
            assert len(group_methods) > 0
