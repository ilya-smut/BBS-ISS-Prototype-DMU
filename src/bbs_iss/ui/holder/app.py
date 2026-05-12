"""
Flask UI application for the Holder entity.

Provides a browser-based interface for registry sync,
credential issuance, and protocol trail inspection.
"""

import os
from datetime import datetime, timedelta, timezone
from threading import Thread

from flask import Flask, render_template, request, redirect, url_for, flash

from bbs_iss.endpoints.orchestrator import HolderOrchestrator
from bbs_iss.endpoints.trail import RequestTrail
import bbs_iss.interfaces.requests_api as api
import bbs_iss.utils.utils as utils


class HolderAppState:
    """Shared state between the Flask UI and the Holder orchestrator."""

    def __init__(self, orch: HolderOrchestrator):
        self.orch = orch
        self.trails: list[RequestTrail] = []

    def add_trail(self, trail: RequestTrail):
        self.trails.insert(0, trail)  # Most recent first


def create_holder_ui(orch: HolderOrchestrator, port: int = 8004) -> Flask:
    """
    Create and start the Holder UI Flask application.

    Parameters
    ----------
    orch : HolderOrchestrator
        The orchestrator returned by holder_bootstrap().
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
    state = HolderAppState(orch)

    # ── Dashboard ────────────────────────────────────────────────────

    @app.route("/")
    def dashboard():
        credentials = []
        cache = state.orch.entity.public_data_cache
        for name, (vc, pub_key) in state.orch.entity.credentials.items():
            expiry_str = vc.credential_subject.get("validUntil", "")
            try:
                expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
                expired = datetime.now(timezone.utc) > expiry
            except (ValueError, TypeError):
                expired = False

            # Revocation check via cached issuer public data
            revoked = False
            in_reissue_window = False
            rev_index = vc.credential_subject.get("revocationMaterial", "")
            issuer_data = cache.get(vc.issuer)
            if issuer_data and rev_index:
                revoked = issuer_data.check_revocation_status(rev_index)

            # Re-issuance window check
            if issuer_data and not expired and not revoked:
                try:
                    time_left = expiry - datetime.now(timezone.utc)
                    in_reissue_window = time_left <= timedelta(days=issuer_data.validity_window_days)
                except Exception:
                    pass

            credentials.append({
                "name": name,
                "issuer": vc.issuer,
                "expiry": expiry_str,
                "expired": expired,
                "revoked": revoked,
                "in_reissue_window": in_reissue_window,
                "json": vc.to_json(indent=2),
            })

        # Known issuers from cache
        cache = state.orch.entity.public_data_cache
        issuers = []
        for issuer_name, entry in cache._cache.items():
            data = entry.issuer_data
            pk_hex = data.public_key.key.hex()
            issuers.append({
                "name": issuer_name,
                "pk_short": f"{pk_hex[:10]}...{pk_hex[-10:]}",
                "pk_full": pk_hex,
                "bitstring": data.revocation_bitstring,
                "bitstring_bits": len(data.revocation_bitstring) * 4,
                "epoch_days": data.epoch_size_days,
                "reissue_window_days": data.validity_window_days,
                "obtained_at": entry.obtained_at,
            })

        return render_template(
            "dashboard.html",
            credentials=credentials,
            trails=state.trails,
            issuers=issuers,
        )

    # ── Registry Sync ────────────────────────────────────────────────

    @app.route("/sync", methods=["POST"])
    def sync_registry():
        try:
            trail = state.orch.sync_registry()
            state.add_trail(trail)
            if trail.status == "COMPLETED":
                flash("Registry synced successfully.", "success")
            else:
                flash(f"Registry sync failed: {trail.error}", "error")
        except Exception as e:
            flash(f"Registry sync error: {e}", "error")
        return redirect(url_for("dashboard"))

    # ── Issuance Form ────────────────────────────────────────────────

    @app.route("/issue", methods=["GET"])
    def issue_form():
        # Populate issuer dropdown from cache
        cache = state.orch.entity.public_data_cache
        issuer_names = list(cache._cache.keys())
        return render_template("issue.html", issuer_names=issuer_names)

    @app.route("/issue", methods=["POST"])
    def issue_submit():
        issuer_name = request.form.get("issuer_name", "").strip()
        cred_name = request.form.get("cred_name", "").strip()

        if not issuer_name:
            flash("Issuer name is required.", "error")
            return redirect(url_for("issue_form"))
        if not cred_name:
            flash("Credential name is required.", "error")
            return redirect(url_for("issue_form"))

        # Build IssuanceAttributes from form
        attr = api.IssuanceAttributes()

        # Collect dynamic attribute rows
        keys = request.form.getlist("attr_key")
        values = request.form.getlist("attr_value")
        for k, v in zip(keys, values):
            k = k.strip()
            v = v.strip()
            if k and v:
                attr.append(k, v, api.AttributeType.REVEALED)

        # Auto-generate LinkSecret as a hidden attribute
        attr.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)

        # Execute issuance protocol
        trail = state.orch.execute_issuance(
            issuer_name=issuer_name,
            attributes=attr,
            cred_name=cred_name,
        )
        state.add_trail(trail)

        if trail.status == "COMPLETED":
            flash(f"Credential '{cred_name}' issued successfully.", "success")
        else:
            flash(f"Issuance failed: {trail.error}", "error")

        return redirect(url_for("dashboard"))

    # ── Re-issuance ──────────────────────────────────────────────────

    @app.route("/reissue/<vc_name>", methods=["POST"])
    def reissue(vc_name):
        if vc_name not in state.orch.entity.credentials:
            flash(f"Credential '{vc_name}' not found.", "error")
            return redirect(url_for("dashboard"))

        try:
            trail = state.orch.execute_re_issuance(
                vc_name=vc_name,
                always_hidden_keys=["LinkSecret"],
            )
            state.add_trail(trail)
            if trail.status == "COMPLETED":
                flash(f"Credential '{vc_name}' renewed successfully.", "success")
            else:
                flash(f"Re-issuance failed: {trail.error}", "error")
        except Exception as e:
            flash(f"Re-issuance error: {e}", "error")

        return redirect(url_for("dashboard"))

    # ── Start server on daemon thread ────────────────────────────────

    thread = Thread(
        target=app.run,
        kwargs={"host": "0.0.0.0", "port": port, "debug": False},
        daemon=True,
    )
    thread.start()

    return app
