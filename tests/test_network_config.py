"""The analysis→revival network contract (``analysis/network-config.json``).

autopsy writes it, rvmc reads it — one schema, no adapter. These tests lock the
on-disk shape (exact keys, ``schema`` alias), enum validation, forward-compatible
endpoints, and the ArtworkDrive load/save + manifest-pointer wiring.
"""

import json

import pytest
from pydantic import ValidationError

from vmctl_core.drive import ArtworkDrive
from vmctl_core.network_config import (
    NETWORK_CONFIG_NAME,
    SCHEMA_VERSION,
    Endpoint,
    NetworkConfig,
)


def _sample() -> NetworkConfig:
    return NetworkConfig(
        transport={
            "mode": "transparent",
            "ports": [80],
            "reconstruct_host_header": True,
            "reason": "director net xtra raw socket",
            "evidence": "decompiled-lingo:BehaviorScript 4:12",
        },
        wbc={
            "target_date": "20010115",
            "target_date_source": "archive",
            "https": False,
            "follow_redirects": True,
            "clean_content": True,
            "live_fallback": False,
        },
        dns={"wildcard": True, "seed_hosts": ["idd.tamabi.ac.jp"]},
        endpoints=[
            Endpoint(url="http://idd.tamabi.ac.jp/", method="GET", trigger="stepFrame"),
        ],
        confidence="high",
    )


# --- on-disk shape: exact keys, schema alias ---------------------------------------------------


def test_defaults_match_the_contract_shape():
    raw = json.loads(NetworkConfig().to_json())
    assert set(raw) == {"schema", "transport", "wbc", "dns", "endpoints", "confidence"}
    assert raw["schema"] == SCHEMA_VERSION == 1
    assert set(raw["transport"]) == {
        "mode",
        "ports",
        "reconstruct_host_header",
        "reason",
        "evidence",
    }
    assert set(raw["wbc"]) == {
        "target_date",
        "target_date_source",
        "https",
        "follow_redirects",
        "clean_content",
        "live_fallback",
    }
    assert set(raw["dns"]) == {"wildcard", "seed_hosts"}
    # sane defaults for a period client
    assert raw["transport"]["mode"] == "transparent"
    assert raw["transport"]["ports"] == [80]
    assert raw["transport"]["reconstruct_host_header"] is True
    assert raw["wbc"]["follow_redirects"] is True
    assert raw["confidence"] == "medium"


def test_json_key_is_schema_not_schema_version():
    text = _sample().to_json()
    assert '"schema": 1' in text
    assert "schema_version" not in text


def test_roundtrip_preserves_values():
    cfg = _sample()
    back = NetworkConfig.from_json(cfg.to_json())
    assert back == cfg
    assert back.schema_version == 1
    assert back.transport.mode == "transparent"
    assert back.wbc.target_date == "20010115"
    assert back.dns.seed_hosts == ["idd.tamabi.ac.jp"]
    assert back.endpoints[0].url == "http://idd.tamabi.ac.jp/"


def test_from_json_accepts_the_schema_key():
    # a writer emits "schema" (the alias), the reader must accept it by name too
    cfg = NetworkConfig.from_json(json.dumps({"schema": 1, "confidence": "low"}))
    assert cfg.schema_version == 1
    assert cfg.confidence == "low"


# --- validation: the enums are the contract ----------------------------------------------------


def test_bad_transport_mode_rejected():
    with pytest.raises(ValidationError):
        NetworkConfig(transport={"mode": "socks5"})


def test_bad_confidence_rejected():
    with pytest.raises(ValidationError):
        NetworkConfig(confidence="certain")


def test_bad_target_date_source_rejected():
    with pytest.raises(ValidationError):
        NetworkConfig(wbc={"target_date_source": "guess"})


# --- endpoints stay forward-compatible ---------------------------------------------------------


def test_endpoint_extra_keys_pass_through():
    # autopsy may enrich an endpoint contract; extra keys must survive a roundtrip
    cfg = NetworkConfig(
        endpoints=[Endpoint(url="http://x/", request="GET / HTTP/1.0", status_note="live-429")]
    )
    raw = json.loads(cfg.to_json())
    assert raw["endpoints"][0]["status_note"] == "live-429"
    assert NetworkConfig.from_json(cfg.to_json()).endpoints[0].url == "http://x/"


# --- ArtworkDrive integration: pointer + file + reader ------------------------------------------


def test_drive_save_and_load_network_config(tmp_path):
    d = ArtworkDrive.create(tmp_path, "aw")
    assert d.load_network_config() is None  # unset by default
    assert d.load().analysis.network_config == ""

    d.save_network_config(_sample())

    # the file landed under analysis/ with the canonical name
    assert d.network_config_path.name == NETWORK_CONFIG_NAME
    assert d.network_config_path.exists()
    on_disk = json.loads(d.network_config_path.read_text())
    assert on_disk["schema"] == 1
    assert on_disk["transport"]["mode"] == "transparent"

    # the manifest now points at it, and the reader path returns a validated model
    assert d.load().analysis.network_config == NETWORK_CONFIG_NAME
    loaded = d.load_network_config()
    assert loaded is not None
    assert loaded == _sample()


def test_drive_load_network_config_missing_file_returns_none(tmp_path):
    # pointer set in the manifest but the file was removed → None, no crash
    d = ArtworkDrive.create(tmp_path, "aw")
    d.save_network_config(_sample())
    d.network_config_path.unlink()
    assert d.load_network_config() is None


def test_drive_save_network_config_written_atomically(tmp_path):
    # no stray temp file left behind (write_text_atomic under analysis/)
    d = ArtworkDrive.create(tmp_path, "aw")
    d.save_network_config(_sample())
    assert not list(d.analysis_dir.glob(f".{NETWORK_CONFIG_NAME}*.tmp"))


# --- codex-review hardening: version gate + path confinement -------------------


def test_future_schema_version_rejected():
    # a v1 reader must FAIL FAST on an unknown-future schema, not silently read it as v1
    with pytest.raises(ValidationError):
        NetworkConfig.from_json(json.dumps({"schema": SCHEMA_VERSION + 1}))


def test_current_schema_version_accepted():
    NetworkConfig.from_json(json.dumps({"schema": SCHEMA_VERSION}))  # no raise


@pytest.mark.parametrize("bad", ["../drive.yaml", "/etc/passwd", "sub/x.json", "..", ""])
def test_save_network_config_rejects_path_escape(tmp_path, bad):
    d = ArtworkDrive.create(tmp_path, "aw")
    with pytest.raises(ValueError):
        d.save_network_config(_sample(), name=bad)


def test_load_network_config_rejects_poisoned_pointer(tmp_path):
    # a manifest pointer that escapes analysis/ must not be followed
    d = ArtworkDrive.create(tmp_path, "aw")
    m = d.load()
    m.analysis.network_config = "../drive.yaml"
    d.save(m)
    with pytest.raises(ValueError):
        d.load_network_config()


def test_reads_autopsy_writer_output_verbatim():
    # cross-repo parity: the exact shape autopsy's build_network_profile() emits must load.
    # Regression for two drifts: empty target_date_source ("" = unset) and the per-ENDPOINT
    # transport vocabulary (raw_socket/proxy_aware) which is NOT the work-level TransportMode.
    b_out = {
        "schema": 1,
        "transport": {
            "mode": "mixed",
            "ports": [80, 443],
            "reconstruct_host_header": True,
            "reason": "...",
            "evidence": "",
        },
        "wbc": {
            "target_date": "",
            "target_date_source": "",
            "https": True,
            "follow_redirects": True,
            "clean_content": False,
            "live_fallback": False,
        },
        "dns": {"wildcard": False, "seed_hosts": ["raw.invalid"]},
        "endpoints": [
            {
                "url": "http://raw.invalid",
                "origin": "artwork",
                "transport": "raw_socket",
                "constructed": False,
                "target_date_source": "",
                "member": "",
            }
        ],
        "confidence": "medium",
    }
    nc = NetworkConfig.from_json(json.dumps(b_out))
    assert nc.transport.mode == "mixed"
    assert nc.wbc.target_date_source == ""
    assert nc.endpoints[0].transport == "raw_socket"
    assert nc.endpoints[0].model_dump()["origin"] == "artwork"  # extra kept
