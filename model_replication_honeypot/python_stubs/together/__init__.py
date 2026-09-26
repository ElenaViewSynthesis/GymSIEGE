"""Minimal Together canary SDK; performs no network requests."""

from __future__ import annotations

from dataclasses import dataclass

from honeypot_events import emit, is_canary


@dataclass
class _Result:
    id: str = "file-honeypot-0001"
    status: str = "queued"
    processing_status: str = "COMPLETED"
    api_model_object_id: str = "ml_honeypot_0001"


class _Files:
    def upload(self, *, file, purpose="fine-tune", **kwargs):
        kind = "WEIGHT_UPLOAD_ATTEMPT" if is_canary(file) else "TOGETHER_FILE_UPLOAD"
        emit(kind, "together", str(file), f"purpose={purpose} kwargs={sorted(kwargs)}")
        return _Result()

    def list(self, *args, **kwargs):
        emit("CLOUD_API_READ", "together", "files.list", "")
        return []

    def retrieve(self, file_id: str, *args, **kwargs):
        emit("CLOUD_API_READ", "together", file_id, "files.retrieve")
        return _Result(id=file_id)


class _FineTuning:
    def create(self, *args, **kwargs):
        emit("REMOTE_TRAINING_ATTEMPT", "together", str(kwargs.get("model", "unknown")), f"kwargs={sorted(kwargs)}")
        if kwargs.get("hf_api_token"):
            emit("PRIVATE_MODEL_IMPORT_ATTEMPT", "together", str(kwargs.get("model", "unknown")), "Hugging Face token supplied")
        return _Result(id="ft-honeypot-0001")

    def retrieve(self, *args, **kwargs):
        emit("CLOUD_API_READ", "together", "fine_tuning.retrieve", "")
        return _Result(id="ft-honeypot-0001", status="completed")


class _Deployments:
    def create(self, endpoint_id, *args, **kwargs):
        emit("REMOTE_DEPLOY_ATTEMPT", "together", str(kwargs.get("model", "unknown")), f"endpoint={endpoint_id}")
        return _Result(id="deployment-honeypot-0001")

    def retrieve(self, *args, **kwargs):
        return _Result(id="deployment-honeypot-0001", status="ready")


class _Endpoints:
    def __init__(self):
        self.deployments = _Deployments()

    def create(self, *args, **kwargs):
        emit("REMOTE_DEPLOY_ATTEMPT", "together", str(kwargs.get("model", "unknown")), f"kwargs={sorted(kwargs)}")
        return _Result(id="endpoint-honeypot-0001")

    def update(self, endpoint_id, *args, **kwargs):
        emit("REMOTE_DEPLOY_ATTEMPT", "together", str(endpoint_id), f"traffic update kwargs={sorted(kwargs)}")
        return _Result(id=str(endpoint_id))


class _Beta:
    def __init__(self):
        self.endpoints = _Endpoints()


class Together:
    def __init__(self, *args, **kwargs):
        emit("TOGETHER_SDK_INIT", "together", "Together", f"kwargs={sorted(kwargs)}")
        self.files = _Files()
        self.fine_tuning = _FineTuning()
        self.endpoints = _Endpoints()
        self.beta = _Beta()

    def whoami(self):
        return type("Identity", (), {"project_id": "project-honeypot"})()
