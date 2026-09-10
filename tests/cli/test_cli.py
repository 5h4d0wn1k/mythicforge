"""Tests for the CLI module."""

import argparse
import os
import sys

import pytest
from mythicforge.cli.main import (
    build_parser,
    cmd_demo,
    cmd_list_attacks,
    cmd_list_suites,
    cmd_list_techniques,
    main,
)


class TestArgParser:
    def test_parser_creation(self):
        parser = build_parser()
        assert parser is not None
        assert parser.prog == "mythicforge"

    def test_demo_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--demo"])
        assert args.demo is True

    def test_target_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--target", "openai"])
        assert args.target == "openai"

    def test_model_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--model", "gpt-4o"])
        assert args.model == "gpt-4o"

    def test_api_key_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--api-key", "sk-test"])
        assert args.api_key == "sk-test"

    def test_base_url_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--base-url", "http://localhost:8080"])
        assert args.base_url == "http://localhost:8080"

    def test_bench_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--bench", "owasp_top10_2025"])
        assert args.bench == "owasp_top10_2025"

    def test_list_techniques_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--list-techniques"])
        assert args.list_techniques is True

    def test_list_suites_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--list-suites"])
        assert args.list_suites is True

    def test_list_attacks_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--list-attacks"])
        assert args.list_attacks is True

    def test_variations_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--variations", "10"])
        assert args.variations == 10

    def test_report_formats_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--report-formats", "json", "html"])
        assert args.report_formats == ["json", "html"]

    def test_output_dir_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--output-dir", "out"])
        assert args.output_dir == "out"

    def test_budget_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--budget", "10"])
        assert args.budget == 10.0

    def test_verbose_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--verbose"])
        assert args.verbose is True

    def test_quiet_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--quiet"])
        assert args.quiet is True

    def test_defaults(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.target is None
        assert args.model == "gpt-4"
        assert args.variations == 0
        assert args.output_dir == "reports"
        assert args.budget == 100.0


class TestMainDispatch:
    def test_main_no_args_returns_zero(self, capsys):
        code = main([])
        assert code == 0

    def test_main_list_techniques(self, capsys):
        code = main(["--list-techniques"])
        assert code == 0
        output = capsys.readouterr().out
        assert "Attack Techniques" in output

    def test_main_list_suites(self, capsys):
        code = main(["--list-suites"])
        assert code == 0
        output = capsys.readouterr().out
        assert "Benchmark Suites" in output

    def test_main_list_attacks(self, capsys):
        code = main(["--list-attacks"])
        assert code == 0
        output = capsys.readouterr().out
        assert "All Attack Payloads" in output

    def test_main_demo(self, capsys, tmp_path):
        code = main(["--demo", "--output-dir", str(tmp_path), "--quiet"])
        assert code == 0
        output = capsys.readouterr().out
        assert "RESULTS SUMMARY" in output

    def test_main_demo_generates_reports(self, tmp_path):
        output = str(tmp_path / "demo_reports")
        main(["--demo", "--output-dir", output, "--quiet"])
        files = os.listdir(output)
        assert any(f.endswith(".json") for f in files)
        assert any(f.endswith(".html") for f in files)

    def test_main_bench_unknown_suite_handled(self, capsys, tmp_path):
        code = main(["--bench", "nonexistent", "--target", "mock", "--output-dir", str(tmp_path)])
        assert code == 0


class TestCmdFunctions:
    def test_cmd_list_techniques(self, capsys):
        code = cmd_list_techniques()
        assert code == 0
        assert "direct_injection" in capsys.readouterr().out

    def test_cmd_list_suites(self, capsys):
        code = cmd_list_suites()
        assert code == 0
        output = capsys.readouterr().out
        assert "owasp_top10_2025" in output
        assert "comprehensive" in output

    def test_cmd_list_attacks(self, capsys):
        code = cmd_list_attacks()
        assert code == 0
        output = capsys.readouterr().out
        assert "All Attack Payloads" in output


class TestDemoMode:
    def test_demo_runs_full_suite(self, capsys, tmp_path):
        output = str(tmp_path / "out")
        code = cmd_demo(argparse.Namespace(
            output_dir=output,
            report_formats=["json"],
            quiet=True,
            system_prompt="",
        ))
        assert code == 0
        assert os.path.exists(os.path.join(output, "mythicforge_report.json"))

    def test_demo_verbose_output(self, capsys, tmp_path):
        output = str(tmp_path / "vout")
        cmd_demo(argparse.Namespace(
            output_dir=output,
            report_formats=["json"],
            quiet=False,
            system_prompt="",
        ))
        out = capsys.readouterr().out
        assert "BYPASSED" in out or "BLOCKED" in out

    def test_demo_executes_all_attacks(self, capsys, tmp_path):
        from mythicforge.attacks import AttackLibrary
        output = str(tmp_path / "out")
        cmd_demo(argparse.Namespace(
            output_dir=output,
            report_formats=["json"],
            quiet=True,
            system_prompt="",
        ))
        with open(os.path.join(output, "mythicforge_report.json")) as f:
            import json
            data = json.load(f)
        assert data["summary"]["total_attacks"] == AttackLibrary().get_attack_count()

    def test_demo_system_prompt(self, capsys, tmp_path):
        output = str(tmp_path / "sp")
        code = cmd_demo(argparse.Namespace(
            output_dir=output,
            report_formats=["json"],
            quiet=True,
            system_prompt="You are a secure assistant.",
        ))
        assert code == 0