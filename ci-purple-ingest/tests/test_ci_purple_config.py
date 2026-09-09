"""
Contract tests for `ci_purple_config` and its wiring into the CLI's settings resolution.

The load-bearing property is the PRECEDENCE ORDER -- CLI flag > environment > config.ini >
built-in default. Config sits below the environment on purpose, so a stale `config.ini` left in a
working copy can never silently override what a CI runner injected. That is exactly the kind of
ordering that breaks without anyone noticing, so it is pinned here rather than only documented.
"""

import argparse
import os

import pytest

import ci_purple_sbom_to_phoenix as cli
from ci_purple_config import CiPurpleConfigFileError, load_config

DEFAULT_BASE_URL = "https://api.securityphoenix.cloud"


def write_config(tmp_path, body):
    path = tmp_path / "config.ini"
    path.write_text(body, encoding="utf-8")
    return str(path)


def args_ns(**overrides):
    base = dict(
        api_key=None, api_base_url=None, allow_insecure_http=False, verify_tls=False,
        no_verify_tls=False, ca_bundle=None, timeout_seconds=60, max_retry_attempts=5,
        retry_base_delay_seconds=1.0, retry_max_delay_seconds=30.0, config=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("PHOENIX_API_KEY", raising=False)
    monkeypatch.delenv("PHOENIX_API_BASE_URL", raising=False)


LOCAL_STACK = """
[phoenix]
api_base_url = http://localhost:4300
allow_insecure_http = true

[auth]
api_key = config-supplied-key
"""


def test_config_supplies_base_url_key_and_insecure_flag(tmp_path):
    file_cfg = load_config(write_config(tmp_path, LOCAL_STACK), required=True)
    cfg, exit_code = cli._resolve_client_config(args_ns(), file_cfg)
    assert exit_code is None
    assert cfg.api_base_url == "http://localhost:4300"
    assert cfg.api_key == "config-supplied-key"
    # Without allow_insecure_http the http:// URL is refused, so this proves the key is honoured.
    assert cfg.allow_insecure_http is True


def test_environment_beats_config(tmp_path, monkeypatch):
    file_cfg = load_config(write_config(tmp_path, LOCAL_STACK), required=True)
    monkeypatch.setenv("PHOENIX_API_BASE_URL", "http://localhost:4350")
    cfg, _ = cli._resolve_client_config(args_ns(), file_cfg)
    assert cfg.api_base_url == "http://localhost:4350"


def test_flag_beats_environment_and_config(tmp_path, monkeypatch):
    file_cfg = load_config(write_config(tmp_path, LOCAL_STACK), required=True)
    monkeypatch.setenv("PHOENIX_API_BASE_URL", "http://localhost:4350")
    cfg, _ = cli._resolve_client_config(args_ns(api_base_url="https://flag.example.com"), file_cfg)
    assert cfg.api_base_url == "https://flag.example.com"


def test_absent_config_falls_through_to_the_builtin_default(tmp_path, monkeypatch):
    monkeypatch.setenv("PHOENIX_API_KEY", "env-key")
    file_cfg = load_config(str(tmp_path / "nope.ini"), required=False)
    assert len(file_cfg) == 0
    cfg, exit_code = cli._resolve_client_config(args_ns(), file_cfg)
    assert exit_code is None
    assert cfg.api_base_url == DEFAULT_BASE_URL


def test_explicitly_requested_missing_config_is_an_error(tmp_path):
    with pytest.raises(CiPurpleConfigFileError):
        load_config(str(tmp_path / "nope.ini"), required=True)


def test_unparseable_config_is_an_error(tmp_path):
    path = tmp_path / "bad.ini"
    path.write_text("not ini at all [[[\n", encoding="utf-8")
    with pytest.raises(CiPurpleConfigFileError):
        load_config(str(path), required=True)


def test_unknown_keys_are_ignored_not_trusted(tmp_path):
    path = write_config(tmp_path, "[phoenix]\napi_base_url = https://a.example.com\nnot_a_real_key = x\n")
    file_cfg = load_config(path, required=True)
    assert file_cfg.get("api_base_url") == "https://a.example.com"
    assert file_cfg.get("not_a_real_key") is None


def test_non_boolean_flag_value_is_rejected(tmp_path):
    path = write_config(tmp_path, "[phoenix]\nallow_insecure_http = perhaps\n")
    file_cfg = load_config(path, required=True)
    with pytest.raises(CiPurpleConfigFileError):
        file_cfg.get_bool("allow_insecure_http")


def test_describe_source_never_reveals_a_value(tmp_path):
    """Rule 05 #3: report WHICH file supplied settings, never WHAT they were."""
    path = write_config(tmp_path, LOCAL_STACK)
    described = load_config(path, required=True).describe_source()
    assert "config-supplied-key" not in described
    assert "localhost:4300" not in described
    assert path in described


def test_load_file_config_reports_a_bad_path_without_raising(tmp_path, capsys):
    """`--config <missing>` must exit 1 with this tool's own error line, never a traceback."""
    file_cfg, exit_code = cli._load_file_config(args_ns(config=str(tmp_path / "nope.ini")))
    assert file_cfg is None and exit_code == 1
    assert "config file not found" in capsys.readouterr().err
