"""Public libvirt snapshot operations, exercised at the virsh process boundary."""

import subprocess

import pytest

from vmctl_core.backends import BackendError, LibvirtBackend


class Runner:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.calls = []

    def __call__(self, argv, timeout, check):
        assert argv[:3] == ["virsh", "-c", "test:///local"]
        self.calls.append((argv[3:], timeout, check))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        if isinstance(response, str):
            return subprocess.CompletedProcess(argv, 0, stdout=response, stderr="")
        return response


def backend(*responses):
    runner = Runner(*responses)
    return LibvirtBackend("vm", "test:///local", runner=runner), runner.calls


def failed(stderr):
    return subprocess.CompletedProcess(["virsh"], 1, stdout="", stderr=stderr)


def test_runner_handles_lifecycle_and_domain_definition():
    domain, calls = backend(failed("Domain is not running"), "")
    domain.stop()
    domain.define("test.xml")
    assert calls == [(["destroy", "vm"], 30, False), (["define", "test.xml"], 30, True)]


def test_create_without_replacing():
    domain, calls = backend("<domain/>", "")
    domain.snapshot_create("ready", description="test baseline", replace=False, timeout=75)
    assert calls[0] == (["dumpxml", "vm"], 30, True)
    args, timeout, check = calls[1]
    assert args[:3] == ["snapshot-create-as", "vm", "ready"]
    assert "--atomic" in args[3:]
    assert args[args.index("--description") + 1] == "test baseline"
    assert (timeout, check) == (75, True)


def test_delete_with_children_and_timeout():
    domain, calls = backend("")
    domain.snapshot_delete("ready", children=True, timeout=55)
    assert calls == [(["snapshot-delete", "vm", "ready", "--children"], 55, True)]


@pytest.mark.parametrize("stderr", ["No snapshot with name 'ready'", "Domain Snapshot Not Found"])
def test_delete_missing_ok(stderr):
    domain, _ = backend(failed(stderr), failed(stderr))
    domain.snapshot_delete("ready", missing_ok=True)
    with pytest.raises(BackendError, match=stderr):
        domain.snapshot_delete("ready")


def test_delete_missing_ok_propagates_other_errors():
    domain, _ = backend(failed("permission denied"), subprocess.TimeoutExpired("virsh", 42))
    with pytest.raises(BackendError, match="permission denied"):
        domain.snapshot_delete("No snapshot with name", missing_ok=True)
    with pytest.raises(BackendError, match="timed out after 42s"):
        domain.snapshot_delete("ready", missing_ok=True, timeout=42)


@pytest.mark.parametrize(
    ("options", "flags"),
    [
        ({}, ["--snapshots-metadata"]),  # the default rvmc's undefine() relies on
        ({"snapshots_metadata": False}, []),
        ({"nvram": True}, ["--snapshots-metadata", "--nvram"]),
        ({"snapshots_metadata": False, "nvram": True}, ["--nvram"]),
    ],
)
def test_undefine_flags(options, flags):
    domain, calls = backend("<domain/>", "")
    domain.undefine(**options)
    assert calls == [(["dumpxml", "vm"], 30, True), (["undefine", "vm", *flags], 30, False)]


STAGING = "ready__staging"
DELETE_STAGING = ["snapshot-delete", "vm", STAGING]
CREATE_STAGING = ["snapshot-create-as", "vm", STAGING]
LIST = ["snapshot-list", "vm", "--name"]
DELETE_READY = ["snapshot-delete", "vm", "ready"]
CREATE_READY = ["snapshot-create-as", "vm", "ready"]


def test_refresh_order_and_deadlines():
    domain, calls = backend(failed("No snapshot with name"), "", STAGING + "\n", "", "", "")
    domain.refresh_snapshot("ready", timeout=90, cleanup_timeout=45)
    assert [(args, timeout) for args, timeout, _ in calls] == [
        (DELETE_STAGING, 45),
        (CREATE_STAGING, 90),
        (LIST, 30),
        (DELETE_READY, 45),
        (CREATE_READY, 90),
        (DELETE_STAGING, 45),
    ]


@pytest.mark.parametrize(
    ("responses", "message", "commands"),
    [
        (["", failed("staging failed")], "staging failed", [DELETE_STAGING, CREATE_STAGING]),
        (
            ["", "", failed("list failed")],
            "list failed",
            [DELETE_STAGING, CREATE_STAGING, LIST],
        ),
        (
            ["", "", "ready\nready__staging2\n", ""],
            "Staging snapshot 'ready__staging' not found after creation - refusing to "
            "delete the existing 'ready' snapshot",
            [DELETE_STAGING, CREATE_STAGING, LIST, DELETE_STAGING],
        ),
    ],
)
def test_refresh_failure_before_retiring_old_snapshot(responses, message, commands):
    domain, calls = backend(*responses)
    with pytest.raises(BackendError, match=message):
        domain.refresh_snapshot("ready")
    assert [args for args, _, _ in calls] == commands


@pytest.mark.parametrize(
    "error",
    [
        subprocess.CalledProcessError(1, "virsh", stderr="create failed"),
        subprocess.TimeoutExpired("virsh", 120),
    ],
)
def test_refresh_keeps_verified_staging_on_final_failure(error, caplog):
    domain, calls = backend("", "", STAGING, "", error)
    with pytest.raises(BackendError, match="kept as a recovery point"):
        domain.refresh_snapshot("ready")
    assert [args for args, _, _ in calls] == [
        DELETE_STAGING,
        CREATE_STAGING,
        LIST,
        DELETE_READY,
        CREATE_READY,
    ]
    assert "the verified snapshot 'ready__staging' has been kept as a recovery point" in caplog.text


def test_refresh_cleanup_is_best_effort(caplog):
    domain, calls = backend(
        failed("permission denied"),
        "",
        STAGING,
        failed("No snapshot with name"),
        "",
        subprocess.TimeoutExpired("virsh", 60),
    )
    domain.refresh_snapshot("ready")
    assert [(args, timeout) for args, timeout, _ in calls] == [
        (DELETE_STAGING, 60),
        (CREATE_STAGING, 120),
        (LIST, 30),
        (DELETE_READY, 60),
        (CREATE_READY, 120),
        (DELETE_STAGING, 60),
    ]
    assert "Could not delete snapshot 'ready__staging': permission denied" in caplog.text
    assert "Timed out deleting snapshot 'ready__staging'" in caplog.text
    assert "No snapshot with name" not in caplog.text


def test_validate_snapshot_names_before_any_command():
    domain, calls = backend()
    for operation in (
        lambda: domain.snapshot_create("-bad", replace=False),
        lambda: domain.snapshot_delete("../bad", children=True, missing_ok=True),
        lambda: domain.refresh_snapshot(""),
    ):
        with pytest.raises(BackendError, match="invalid snapshot name"):
            operation()
    assert calls == []
