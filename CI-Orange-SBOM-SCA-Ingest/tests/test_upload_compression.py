"""
Gzip compression for large SBOM uploads, and refusal of oversized --scan-type uploads.

COMPRESS_ABOVE_BYTES and UPLOAD_PART_LIMIT_BYTES are monkeypatched down to a few KiB so test files stay small.
"""

import gzip

import pytest

import phoenix_client
from phoenix_client import PhoenixConfig, create_sbom_import, upload_sbom_file


LIMIT = 4096


@pytest.fixture(autouse=True)
def small_limit(monkeypatch):
    monkeypatch.setattr(phoenix_client, "COMPRESS_ABOVE_BYTES", LIMIT)
    monkeypatch.setattr(phoenix_client, "UPLOAD_PART_LIMIT_BYTES", LIMIT)


class FakeResponse:
    def __init__(self, status_code=200, json_body=None):
        self.status_code = status_code
        self._json = json_body if json_body is not None else {"id": "req-1"}
        import json as _json

        self.text = _json.dumps(self._json)

    def json(self):
        return self._json


class RecordingSession:
    """Records the kwargs actually posted, and returns a scripted response."""

    def __init__(self, response=None):
        self.response = response or FakeResponse()
        self.post_kwargs = None

    def post(self, url, **kwargs):
        self.post_kwargs = kwargs
        return self.response


def make_config():
    return PhoenixConfig(
        client_id="id",
        client_secret="secret",
        api_base_url="https://api.example.invalid",
        import_type="merge",
        assessment_name="a",
        verify_tls=True,
        timeout_seconds=5,
        method="sbom",
        project_type="auto",
        wait_for_completion=False,
        poll_interval_seconds=1,
        poll_timeout_seconds=10,
    )


def write_sbom(tmp_path, data):
    sbom = tmp_path / "sbom.json"
    sbom.write_bytes(data)
    return str(sbom)


def sbom_import(session, sbom_path):
    return create_sbom_import(cfg=make_config(), session=session, token="t", sbom_path=sbom_path)


def test_a_file_at_the_limit_is_sent_uncompressed(tmp_path):
    data = b"a" * LIMIT
    session = RecordingSession()

    sbom_import(session, write_sbom(tmp_path, data))

    assert session.post_kwargs["files"]["file"] == ("sbom.json", data, "application/json")


def test_a_file_over_the_limit_is_gzipped(tmp_path):
    data = b"a" * (LIMIT + 1)
    session = RecordingSession()

    sbom_import(session, write_sbom(tmp_path, data))

    filename, content, content_type = session.post_kwargs["files"]["file"]
    assert (filename, content_type) == ("sbom.json.gz", "application/gzip")
    assert gzip.decompress(content) == data


def test_a_scan_type_upload_over_the_limit_is_refused_and_not_sent(tmp_path):
    session = RecordingSession()

    with pytest.raises(RuntimeError, match="--scan-type uploads go through Phoenix's translation service"):
        upload_sbom_file(
            cfg=make_config(),
            session=session,
            token="t",
            sbom_path=write_sbom(tmp_path, b"a" * (LIMIT + 1)),
            repo="acme/api",
            file_path="pom.xml",
            auto_import=True,
            scan_target=None,
        )

    assert session.post_kwargs is None

