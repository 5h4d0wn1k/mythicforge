"""Tests for utility functions."""

import json
import os
import tempfile

import pytest
from mythicforge.utils import (
    Timer,
    compute_hash,
    ensure_dir,
    format_cost,
    format_duration,
    format_tokens,
    get_timestamp,
    load_json,
    safe_filename,
    save_json,
)


class TestHashFunctions:
    def test_compute_hash(self):
        h = compute_hash("test")
        assert len(h) == 64
        assert isinstance(h, str)

    def test_hash_deterministic(self):
        a = compute_hash("mythicforge")
        b = compute_hash("mythicforge")
        assert a == b

    def test_hash_different_inputs(self):
        a = compute_hash("a")
        b = compute_hash("b")
        assert a != b

    def test_hash_empty_string(self):
        assert len(compute_hash("")) == 64


class TestFormatFunctions:
    def test_format_tokens_basic(self):
        assert format_tokens(42) == "42"

    def test_format_tokens_thousands(self):
        assert format_tokens(1500) == "1.5K"

    def test_format_tokens_millions(self):
        assert format_tokens(2500000) == "2.5M"

    def test_format_cost_small(self):
        assert format_cost(0.0001) == "$0.000100"

    def test_format_cost_medium(self):
        assert format_cost(0.05) == "$0.0500"

    def test_format_cost_large(self):
        assert format_cost(2.5) == "$2.50"

    def test_format_cost_zero(self):
        assert format_cost(0) == "$0.000000"

    def test_format_duration_ms(self):
        assert format_duration(500) == "500ms"

    def test_format_duration_seconds(self):
        assert format_duration(2500) == "2.5s"

    def test_format_duration_minutes(self):
        assert format_duration(120000) == "2.0min"


class TestFileHelpers:
    def test_ensure_dir_creates(self, tmp_path):
        path = ensure_dir(str(tmp_path / "a" / "b"))
        assert path.exists()
        assert path.is_dir()

    def test_ensure_dir_existing(self, tmp_path):
        existing = tmp_path / "x"
        existing.mkdir()
        path = ensure_dir(str(existing))
        assert path == existing

    def test_save_and_load_json(self, tmp_path):
        path = str(tmp_path / "data.json")
        data = {"key": "value", "nested": {"a": 1}}
        save_json(data, path)
        loaded = load_json(path)
        assert loaded == data

    def test_save_json_creates_dirs(self, tmp_path):
        path = str(tmp_path / "a" / "b" / "data.json")
        save_json({"x": 1}, path)
        assert os.path.exists(path)

    def test_load_json_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_json(str(tmp_path / "nope.json"))


class TestTimestamp:
    def test_get_timestamp_iso(self):
        ts = get_timestamp()
        assert "T" in ts
        assert ts.count("-") >= 2

    def test_timestamp_changes(self):
        import time
        a = get_timestamp()
        time.sleep(0.01)
        b = get_timestamp()
        assert a <= b


class TestSafeFilename:
    def test_alphanumeric_pass(self):
        assert safe_filename("mythicforge1") == "mythicforge1"

    def test_spaces_replaced(self):
        assert " " not in safe_filename("my report")

    def test_special_chars_replaced(self):
        assert safe_filename("a/b\\c:") == "a_b_c_"

    def test_keep_dashes(self):
        assert safe_filename("my-report-file") == "my-report-file"


class TestTimer:
    def test_elapsed(self):
        timer = Timer()
        import time
        time.sleep(0.01)
        assert timer.elapsed() >= 0.01

    def test_lap(self):
        timer = Timer()
        first = timer.lap()
        assert first >= 0
        second = timer.lap()
        assert second >= 0

    def test_reset(self):
        timer = Timer()
        timer.lap()
        timer.reset()
        assert timer.elapsed() < 1.0

    def test_multi_laps(self):
        timer = Timer()
        laps = [timer.lap() for _ in range(5)]
        assert len(laps) == 5