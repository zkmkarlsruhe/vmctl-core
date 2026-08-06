"""The analysis→revival network contract (``analysis/network-config.json``).

One schema, shared by construction: **autopsy writes it, rvmc reads it** — no
adapter on either side. autopsy's transport detection (raw-socket vs proxy-aware
period clients) and per-endpoint revival contracts are handed to rvmc's wayback /
transparent-intercept layer through this single file, so the transport decision is
carried across the handoff instead of being rediscovered by hand at the VM layer.

The file lives under a drive's ``analysis/`` dir; the manifest points at it via
:attr:`vmctl_core.drive.AnalysisRef.network_config`. Keys mirror rvmc's plugin
``wbc:`` config map exactly (``target_date``, ``follow_redirects``,
``clean_content``, ``live_fallback``, …) so rvmc consumes it directly.

Schema version 1 — bump :data:`SCHEMA_VERSION` (and the ``schema`` field default)
on any breaking key change.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .atomicio import write_text_atomic

#: current contract schema version (the ``schema`` field value writers emit)
SCHEMA_VERSION = 1

#: default filename under a drive's ``analysis/`` dir
NETWORK_CONFIG_NAME = "network-config.json"

# Work-level intercept mode (how rvmc plumbs the whole VM's :80/:443).
TransportMode = Literal["transparent", "wininet_proxy", "mixed"]
# Per-ENDPOINT transport classification (a different vocabulary than the work-level mode):
# a raw-socket client ignores the WinInet proxy; a proxy-aware one honours it. "" = unclassified.
# autopsy (the writer) emits these; do NOT reuse TransportMode here — they are not the same axis.
EndpointTransport = Literal["", "raw_socket", "proxy_aware"]
# "" = source unknown/unset (autopsy emits "" when it can't date the target).
TargetDateSource = Literal["", "archive", "human", "authoring-era"]
Confidence = Literal["low", "medium", "high"]


class Transport(BaseModel):
    """How the work reaches the network — the raw-socket vs proxy-aware decision.

    ``transparent`` = period client doing its own DNS + origin-form ``GET / HTTP/1.0``
    straight to IP:80 (Director net Xtras, Flash ``URLLoader``, applets, custom
    Winsock); rvmc must DNAT/REDIRECT it. ``wininet_proxy`` = honours the system
    proxy. ``mixed`` = both surfaces present.
    """

    mode: TransportMode = "transparent"
    ports: list[int] = Field(default_factory=lambda: [80])
    #: reconstruct the absolute-URI from the ``Host:`` header on the transparent path
    reconstruct_host_header: bool = True
    reason: str = ""
    #: evidence pointer, ``label:path:line`` (e.g. decompiled-lingo:BehaviorScript 4:12)
    evidence: str = ""


class Wbc(BaseModel):
    """wayback-cache-proxy knobs — keys align 1:1 with rvmc's ``wbc:`` config map."""

    #: YYYYMMDD snapshot pin (empty = proxy default)
    target_date: str = ""
    target_date_source: TargetDateSource = "archive"
    https: bool = False
    follow_redirects: bool = True
    #: strip the injected header bar / rewrite so raw-byte parsers see clean content
    clean_content: bool = True
    #: fall back to the live origin when the archive has no snapshot
    live_fallback: bool = False


class Dns(BaseModel):
    """DNS handling for dead / constructed hosts."""

    #: wildcard any unresolved name to the gateway (only when the host is user/constructed)
    wildcard: bool = False
    seed_hosts: list[str] = Field(default_factory=list)


class Endpoint(BaseModel):
    """One per-endpoint revival contract.

    The known revival-contract fields are typed; extra keys autopsy adds pass
    through untouched (``extra="allow"``) so a writer can enrich the contract
    without a lock-step schema bump on the reader.
    """

    model_config = ConfigDict(extra="allow")

    #: absolute URL or ``host/path`` the work fetches
    url: str = ""
    host: str = ""
    method: str = "GET"
    #: what makes the work issue the request (UI action, timer, stepFrame, …)
    trigger: str = ""
    #: request ground-truth (headers/body the client sends), free-form
    request: str = ""
    #: what the work expects back (content-type, shape) so revival can be verified
    expected_response: str = ""
    transport: EndpointTransport = ""
    target_date: str = ""
    #: archive ground-truth this endpoint was resolved against (CDX/wayback URL)
    archive: str = ""
    wildcard_dns: bool = False
    clean_content: bool = True


class NetworkConfig(BaseModel):
    """``analysis/network-config.json`` — the full analysis→revival network contract.

    Field name ``schema`` is exposed via alias so the JSON key stays exactly
    ``"schema"`` without shadowing ``BaseModel`` internals (attribute is
    :attr:`schema_version`).
    """

    model_config = ConfigDict(populate_by_name=True)

    schema_version: int = Field(default=SCHEMA_VERSION, alias="schema")

    @field_validator("schema_version")
    @classmethod
    def _known_schema(cls, v: int) -> int:
        # Fail fast on a FUTURE schema this reader can't understand — the whole point of a
        # versioned cross-repo contract. autopsy (writer) and rvmc (reader) evolve independently;
        # accepting an unknown v2 as if it were v1 would silently mis-provision the network
        # intercept. Breaking changes MUST bump SCHEMA_VERSION; additive changes keep v1 and ride
        # the models' forward-compat (Endpoint extra="allow").
        if v > SCHEMA_VERSION:
            raise ValueError(
                f"network-config schema v{v} is newer than this reader supports "
                f"(max v{SCHEMA_VERSION}) — refusing to guess; upgrade vmctl-core"
            )
        return v

    transport: Transport = Field(default_factory=Transport)
    wbc: Wbc = Field(default_factory=Wbc)
    dns: Dns = Field(default_factory=Dns)
    endpoints: list[Endpoint] = Field(default_factory=list)
    confidence: Confidence = "medium"

    # --- (de)serialization — mirrors project.py: json + write_text_atomic --------
    def to_json(self) -> str:
        """Render to the on-disk JSON string (``schema`` key, stable 2-space indent)."""
        return json.dumps(self.model_dump(by_alias=True), indent=2)

    @classmethod
    def from_json(cls, text: str) -> NetworkConfig:
        """Parse + validate an on-disk JSON string."""
        return cls.model_validate(json.loads(text))

    @classmethod
    def load(cls, path: str | Path) -> NetworkConfig:
        """Read + validate ``network-config.json`` from ``path``."""
        return cls.from_json(Path(path).read_text())

    def save(self, path: str | Path) -> None:
        """Atomically write ``network-config.json`` to ``path`` (torn-write safe)."""
        write_text_atomic(path, self.to_json())
