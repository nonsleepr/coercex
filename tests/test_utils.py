"""Tests for utility functions: UNC path building, error classification, helpers."""

from __future__ import annotations

import pytest

from coercex.errors import classify_error
from coercex.models import Transport, TriggerResult
from coercex.net import random_string
from coercex.unc import build_unc_path


# -- build_unc_path -----------------------------------------------------------


class TestBuildUncPath:
    """Test UNC path construction for all styles and transports."""

    def test_share_file_smb(self):
        result = build_unc_path(
            "10.0.0.1", "abc123", Transport.SMB, path_style="share_file"
        )
        assert result == "\\\\10.0.0.1\\abc123\\file.txt\x00"

    def test_share_trailing_smb(self):
        result = build_unc_path(
            "10.0.0.1", "abc123", Transport.SMB, path_style="share_trailing"
        )
        assert result == "\\\\10.0.0.1\\abc123\\\x00"

    def test_share_smb(self):
        result = build_unc_path("10.0.0.1", "abc123", Transport.SMB, path_style="share")
        assert result == "\\\\10.0.0.1\\abc123\x00"

    def test_bare_smb(self):
        result = build_unc_path("10.0.0.1", "abc123", Transport.SMB, path_style="bare")
        assert result == "\\\\10.0.0.1\x00"

    def test_unc_device(self):
        result = build_unc_path(
            "10.0.0.1", "abc123", Transport.SMB, path_style="unc_device"
        )
        assert result == "\\??\\UNC\\10.0.0.1\\abc123\\aa"

    def test_http_default_port(self):
        result = build_unc_path(
            "10.0.0.1", "abc123", Transport.HTTP, path_style="share_file"
        )
        assert result == "\\\\10.0.0.1@80\\abc123\\file.txt\x00"

    def test_http_custom_port(self):
        result = build_unc_path(
            "10.0.0.1", "abc123", Transport.HTTP, port=8080, path_style="share_file"
        )
        assert result == "\\\\10.0.0.1@8080\\abc123\\file.txt\x00"

    def test_smb_standard_port(self):
        result = build_unc_path(
            "10.0.0.1", "abc123", Transport.SMB, port=445, path_style="share"
        )
        assert result == "\\\\10.0.0.1\\abc123\x00"

    def test_smb_nonstandard_port_uses_webdav_format(self):
        result = build_unc_path(
            "10.0.0.1", "abc123", Transport.SMB, port=4445, path_style="share"
        )
        assert result == "\\\\10.0.0.1@4445\\abc123\x00"

    def test_unknown_style_defaults_to_share(self):
        result = build_unc_path(
            "10.0.0.1", "abc123", Transport.SMB, path_style="nonexistent"
        )
        assert result == "\\\\10.0.0.1\\abc123\x00"


# -- classify_error -----------------------------------------------------------


class TestClassifyError:
    """Test DCERPC error classification."""

    def test_timeout_error(self):
        assert (
            classify_error(Exception("Connection timed out")) == TriggerResult.TIMEOUT
        )

    def test_connection_refused(self):
        assert classify_error(Exception("Connection refused")) == TriggerResult.TIMEOUT

    def test_connection_reset(self):
        assert (
            classify_error(Exception("Connection reset by peer"))
            == TriggerResult.CONNECT_ERROR
        )

    def test_broken_pipe(self):
        assert classify_error(Exception("Broken pipe")) == TriggerResult.CONNECT_ERROR

    def test_pipe_disconnected(self):
        assert (
            classify_error(Exception("STATUS_PIPE_DISCONNECTED"))
            == TriggerResult.NOT_AVAILABLE
        )

    def test_access_denied_string(self):
        assert classify_error(Exception("access_denied")) == TriggerResult.ACCESS_DENIED

    def test_bad_netpath(self):
        assert classify_error(Exception("bad_netpath")) == TriggerResult.ACCESSIBLE

    def test_bad_net_name(self):
        assert classify_error(Exception("bad_net_name")) == TriggerResult.ACCESSIBLE

    def test_object_name_not_found(self):
        assert (
            classify_error(Exception("object_name_not_found"))
            == TriggerResult.ACCESSIBLE
        )

    def test_unknown_error(self):
        assert (
            classify_error(Exception("something completely unexpected"))
            == TriggerResult.UNKNOWN_ERROR
        )


# -- random_string ------------------------------------------------------------


class TestRandomString:
    def test_default_length(self):
        s = random_string()
        assert len(s) == 8

    def test_custom_length(self):
        s = random_string(16)
        assert len(s) == 16

    def test_alphanumeric(self):
        s = random_string(100)
        assert s.isalnum()
