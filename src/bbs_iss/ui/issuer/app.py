"""
Flask UI application for the Issuer entity.

Provides a browser-based interface for issuer configuration,
issued credential tracking, and revocation management.
"""

import os
from datetime import datetime, timezone
from threading import Thread
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash

from bbs_iss.endpoints.orchestrator import IssuerOrchestrator
from bbs_iss.endpoints.trail import RequestTrail
import bbs_iss.interfaces.requests_api as api
from bbs_iss.interfaces.requests_api import CredentialSchema
from bbs_iss.interfaces.credential import VerifiableCredential


class IssuedCredentialRecord:
    """UI-layer record of a credential the Issuer has signed."""

    def __init__(self, credential_subject: dict, issuer_name: str):
        self.credential_subject = credential_subject
        self.issuer_name = issuer_name
        self.issued_at = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')

    @property
    def revocation_index_hex(self) -> str:
        return self.credential_subject.get("revocationMaterial", "")

    @property
    def valid_until_str(self) -> str:
        return self.credential_subject.get("validUntil", "")

    @property
    def is_expired(self) -> bool:
        try:
            expiry = datetime.fromisoformat(self.valid_until_str.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > expiry
        except (ValueError, TypeError):
            return False

    def is_revoked(self, issuer_entity) -> bool:
        idx_hex = self.revocation_index_hex
        if not idx_hex:
            return False
        try:
            idx = int(idx_hex, 16)
            byte_idx = idx // 8
            bit_offset = idx % 8
            return bool((issuer_entity.bitstring_manager.revocation_bits[byte_idx] >> (7 - bit_offset)) & 1)
        except (ValueError, IndexError):
            return False


class IssuerAppState:
    """Shared state between the Flask UI and the Issuer orchestrator."""

    def __init__(self, orch: IssuerOrchestrator):
        self.orch = orch
        self.trails: list[RequestTrail] = []
        self.issued_credentials: list[IssuedCredentialRecord] = []

    def add_trail(self, trail: RequestTrail):
        self.trails.insert(0, trail)

    def add_credential(self, record: IssuedCredentialRecord):
        self.issued_credentials.insert(0, record)


def create_issuer_ui(orch: IssuerOrchestrator, port: int = 8002) -> Flask:
    """
    Create and start the Issuer UI Flask application.

    Hooks into the entity's process_request to capture issued
    credentials at the UI layer (no changes to issuer.py).

    Parameters
    ----------
    orch : IssuerOrchestrator
        The orchestrator returned by issuer_bootstrap().
    port : int
        Port for the UI server (separate from protocol listener).

    Returns
    -------
    Flask
        The Flask app instance.
    """
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )
    app.secret_key = os.urandom(16)
    state = IssuerAppState(orch)

    # ── Hook into entity.process_request to capture issued VCs ───────

    _original_process = orch.entity.process_request

    @wraps(_original_process)
    def _hooked_process(req):
        result = _original_process(req)
        if isinstance(result, api.ForwardVCResponse):
            record = IssuedCredentialRecord(
                credential_subject=dict(result.vc.credential_subject),
                issuer_name=result.vc.issuer,
            )
            state.add_credential(record)
        return result

    orch.entity.process_request = _hooked_process

    # ── Dashboard ────────────────────────────────────────────────────

    @app.route("/")
    def dashboard():
        entity = state.orch.entity

        # Configuration values
        params = entity.issuer_parameters or {"issuer": "Mock-Issuer"}
        schema = entity.schema
        config = {
            "name": params.get("issuer", "Unknown"),
            "epoch_size_days": entity.epoch_size_days if entity.epoch_size_days is not None else entity.DEFAULT_EPOCH_SIZE_DAYS,
            "reissue_window_days": entity.re_issuance_window_days if entity.re_issuance_window_days is not None else entity.DEFAULT_RE_ISSUANCE_WINDOW_DAYS,
            "baseline_date": entity.baseline_date if entity.baseline_date else entity.DEFAULT_BASELINE_DATE_STR,
            "pk_short": f"{entity.public_key.key.hex()[:10]}...{entity.public_key.key.hex()[-10:]}",
            "bitstring_status": entity.get_bitstring_status(),
            "schema_type": schema.type,
            "schema_context": schema.context,
            "schema_revealed": schema.revealed_attributes,
            "schema_hidden": schema.hidden_attributes,
        }

        # Issued credentials with live status
        creds = []
        for rec in state.issued_credentials:
            # Filter out internal keys from display subject
            display_subject = {
                k: v for k, v in rec.credential_subject.items()
                if k not in ("metaHash", "LinkSecret")
            }
            creds.append({
                "subject": display_subject,
                "issuer": rec.issuer_name,
                "issued_at": rec.issued_at,
                "valid_until": rec.valid_until_str,
                "expired": rec.is_expired,
                "revocation_index": rec.revocation_index_hex,
                "revoked": rec.is_revoked(entity),
            })

        return render_template(
            "dashboard.html",
            config=config,
            credentials=creds,
            trails=state.trails,
        )

    # ── Configuration Update ─────────────────────────────────────────

    @app.route("/configure", methods=["POST"])
    def configure():
        entity = state.orch.entity

        name = request.form.get("issuer_name", "").strip()
        epoch_str = request.form.get("epoch_size_days", "").strip()
        window_str = request.form.get("reissue_window_days", "").strip()
        baseline = request.form.get("baseline_date", "").strip()

        if name:
            entity.set_issuer_parameters({"issuer": name})
        if epoch_str:
            try:
                entity.set_epoch_size_days(int(epoch_str))
            except ValueError:
                flash("Epoch size must be an integer.", "error")
                return redirect(url_for("dashboard"))
        if window_str:
            try:
                entity.set_re_issuance_window_days(int(window_str))
            except ValueError:
                flash("Re-issuance window must be an integer.", "error")
                return redirect(url_for("dashboard"))
        if baseline:
            entity.set_baseline_date(baseline)

        flash("Configuration updated.", "success")
        return redirect(url_for("dashboard"))

    # ── Schema Update ────────────────────────────────────────────────

    # Meta keys appended automatically by build_commitment_append_meta
    _META_KEYS = [
        VerifiableCredential.VALID_UNTIL_KEY,
        VerifiableCredential.REVOCATION_MATERIAL_KEY,
        VerifiableCredential.META_HASH_KEY,
    ]
    _DEFAULT_HIDDEN = ["LinkSecret"]

    @app.route("/update-schema", methods=["POST"])
    def update_schema():
        entity = state.orch.entity

        schema_type = request.form.get("schema_type", "").strip()
        schema_context = request.form.get("schema_context", "").strip()
        attr_keys = request.form.getlist("schema_attr_key")

        if not schema_type:
            flash("Schema type is required.", "error")
            return redirect(url_for("dashboard"))

        # Collect user-provided revealed keys (non-empty, deduplicated, preserving order)
        revealed = []
        seen = set()
        for k in attr_keys:
            k = k.strip()
            if k and k not in seen and k not in _META_KEYS and k not in _DEFAULT_HIDDEN:
                revealed.append(k)
                seen.add(k)

        # Auto-append meta fields at the end of revealed
        revealed.extend(_META_KEYS)

        new_schema = CredentialSchema(
            type=schema_type,
            context=schema_context or f"https://example.org/contexts/{schema_type}",
            revealed_attributes=revealed,
            hidden_attributes=list(_DEFAULT_HIDDEN),
        )
        entity.set_schema(new_schema)

        flash(f"Schema updated to '{schema_type}' with {len(revealed)} revealed + {len(_DEFAULT_HIDDEN)} hidden attributes.", "success")
        return redirect(url_for("dashboard"))

    # ── Register / Update Registry ───────────────────────────────────

    @app.route("/register", methods=["POST"])
    def register_registry():
        try:
            trail = state.orch.register_with_registry()
            state.add_trail(trail)
            if trail.status == "COMPLETED":
                flash("Registered with registry.", "success")
            else:
                flash(f"Registration failed: {trail.error}", "error")
        except Exception as e:
            flash(f"Registration error: {e}", "error")
        return redirect(url_for("dashboard"))

    @app.route("/update-registry", methods=["POST"])
    def update_registry():
        try:
            trail = state.orch.update_registry()
            state.add_trail(trail)
            if trail.status == "COMPLETED":
                flash("Registry updated.", "success")
            else:
                flash(f"Update failed: {trail.error}", "error")
        except Exception as e:
            flash(f"Update error: {e}", "error")
        return redirect(url_for("dashboard"))

    # ── Revoke Credential ────────────────────────────────────────────

    @app.route("/revoke/<int:cred_index>", methods=["POST"])
    def revoke(cred_index):
        entity = state.orch.entity
        if cred_index < 0 or cred_index >= len(state.issued_credentials):
            flash("Invalid credential index.", "error")
            return redirect(url_for("dashboard"))

        rec = state.issued_credentials[cred_index]
        idx_hex = rec.revocation_index_hex
        if not idx_hex:
            flash("Credential has no revocation material.", "error")
            return redirect(url_for("dashboard"))

        if rec.is_revoked(entity):
            flash("Credential is already revoked.", "error")
            return redirect(url_for("dashboard"))

        # Revoke in bitstring
        entity.revoke_index(idx_hex)

        # Update registry so other entities see the revocation
        try:
            trail = state.orch.update_registry()
            state.add_trail(trail)
            if trail.status == "COMPLETED":
                flash(f"Credential at index 0x{idx_hex} revoked and registry updated.", "success")
            else:
                flash(f"Revoked locally but registry update failed: {trail.error}", "error")
        except Exception as e:
            flash(f"Revoked locally but registry update failed: {e}", "error")

        return redirect(url_for("dashboard"))

    # ── Start server on daemon thread ────────────────────────────────

    thread = Thread(
        target=app.run,
        kwargs={"host": "0.0.0.0", "port": port, "debug": False},
        daemon=True,
    )
    thread.start()

    return app
