"""
Flask UI application for the Verifier entity.

Provides a browser-based interface for registry sync,
presentation request creation, and verification result inspection.
"""

import os
from datetime import datetime, timezone
from threading import Thread

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

from bbs_iss.endpoints.orchestrator import VerifierOrchestrator
from bbs_iss.endpoints.trail import RequestTrail
from bbs_iss.exceptions.exceptions import MissingAttributeError
import bbs_iss.interfaces.requests_api as api
from bbs_iss.interfaces.credential import VerifiableCredential


# Meta keys that should not appear as selectable disclosed fields
_META_KEYS = {VerifiableCredential.META_HASH_KEY}


class VerifierAppState:
    """Shared state between the Flask UI and the Verifier orchestrator."""

    def __init__(self, orch: VerifierOrchestrator):
        self.orch = orch
        self.trails: list[RequestTrail] = []
        self.presentation_results: list[dict] = []
        # Track what we last requested so enrichment knows the context
        self._last_requested_attributes: list[str] = []
        self._last_results_count: int = 0

    def add_trail(self, trail: RequestTrail):
        self.trails.insert(0, trail)  # Most recent first

    def check_new_results(self):
        """
        Check if the orchestrator has new verification results and
        enrich them for UI display.
        """
        orch_results = self.orch.verification_results
        if len(orch_results) > self._last_results_count:
            # Process new results
            for raw in orch_results[self._last_results_count:]:
                enriched = self._build_enriched_result(raw)
                self.presentation_results.insert(0, enriched)
            self._last_results_count = len(orch_results)

    def _build_enriched_result(self, raw_result):
        """
        Enrich a raw (is_valid, revealed_attrs, vp) tuple with
        policy-level checks for the UI.
        """
        is_valid, revealed_attrs, vp = raw_result

        # Extract issuer name from VP
        issuer_name = ""
        try:
            issuer_name = vp.verifiableCredential.get("issuer", "Unknown")
        except Exception:
            pass

        result = {
            "crypto_valid": is_valid,
            "all_fields_present": is_valid,  # verify_vp checks completeness
            "revealed_attrs": revealed_attrs or {},
            "requested_attrs": list(self._last_requested_attributes),
            "issuer_name": issuer_name,
            "timestamp": datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z"),
        }

        if not is_valid:
            result["expiration_valid"] = None
            result["revocation_valid"] = None
            result["overall_valid"] = False
            return result

        # ── Expiration check ─────────────────────────────────────
        try:
            result["expiration_valid"] = self.orch.entity.check_validity(vp)
        except MissingAttributeError:
            result["expiration_valid"] = None  # validUntil not disclosed

        # ── Revocation check (only if revocationMaterial disclosed) ──
        if VerifiableCredential.REVOCATION_MATERIAL_KEY in (revealed_attrs or {}):
            try:
                # Ensure we have the issuer's data for bitstring lookup
                if not self.orch.entity.public_data_cache.get(issuer_name):
                    self.orch.sync_registry()
                result["revocation_valid"] = self.orch.entity.check_validity(
                    vp, with_bit_index=True
                )
            except Exception:
                result["revocation_valid"] = None
        else:
            result["revocation_valid"] = None  # Not checkable

        # ── Overall verdict ──────────────────────────────────────
        checks = [result["crypto_valid"], result["all_fields_present"]]
        if result["expiration_valid"] is not None:
            checks.append(result["expiration_valid"])
        if result["revocation_valid"] is not None:
            checks.append(result["revocation_valid"])
        result["overall_valid"] = all(checks)

        return result


def create_verifier_ui(orch: VerifierOrchestrator, port: int = 8003) -> Flask:
    """
    Create and start the Verifier UI Flask application.

    Parameters
    ----------
    orch : VerifierOrchestrator
        The orchestrator returned by verifier_bootstrap().
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
    state = VerifierAppState(orch)

    # ── Dashboard ────────────────────────────────────────────────────

    @app.route("/")
    def dashboard():
        # Check for any new verification results from the orchestrator
        state.check_new_results()

        # Known issuers from cache
        cache = state.orch.entity.public_data_cache
        issuers = []
        for issuer_name, entry in cache._cache.items():
            data = entry.issuer_data
            pk_hex = data.public_key.key.hex()
            schema = data.schema
            issuers.append({
                "name": issuer_name,
                "pk_short": f"{pk_hex[:10]}...{pk_hex[-10:]}",
                "pk_full": pk_hex,
                "bitstring": data.revocation_bitstring,
                "bitstring_bits": len(data.revocation_bitstring) * 4,
                "epoch_days": data.epoch_size_days,
                "reissue_window_days": data.validity_window_days,
                "obtained_at": entry.obtained_at,
                "schema_type": schema.type if schema else None,
                "schema_context": schema.context if schema else None,
                "schema_revealed": schema.revealed_attributes if schema else [],
                "schema_hidden": schema.hidden_attributes if schema else [],
            })

        # Pending request (if Verifier is awaiting a VP response)
        pending = None
        if not state.orch.entity.available:
            # Build a lightweight representation for the template
            entity_state = state.orch.entity.state
            if entity_state.type == api.RequestType.VP_REQUEST:
                freshness_hex = (entity_state.freshness or b"").hex()
                pending = type("PendingRequest", (), {
                    "requested_attributes": entity_state.attributes or [],
                    "nonce": type("Nonce", (), {"hex": lambda self: freshness_hex})(),
                })()

        return render_template(
            "dashboard.html",
            issuers=issuers,
            pending=pending,
            results=state.presentation_results,
            trails=state.trails,
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

    # ── Presentation Request Form ────────────────────────────────────

    @app.route("/request-presentation", methods=["GET"])
    def request_form():
        cache = state.orch.entity.public_data_cache
        issuer_schemas = {}
        for issuer_name, entry in cache._cache.items():
            schema = entry.issuer_data.schema
            if schema:
                # Show all revealed attrs except metaHash (internal)
                user_revealed = [
                    k for k in schema.revealed_attributes if k not in _META_KEYS
                ]
                issuer_schemas[issuer_name] = {
                    "revealed": user_revealed,
                    "hidden": schema.hidden_attributes,
                    "type": schema.type,
                    "context": schema.context,
                }
            else:
                issuer_schemas[issuer_name] = None
        return render_template(
            "request.html",
            issuer_names=list(issuer_schemas.keys()),
            issuer_schemas=issuer_schemas,
        )

    @app.route("/api/schema/<issuer_name>")
    def get_schema(issuer_name):
        """JSON endpoint for dynamic schema loading on issuer change."""
        cache = state.orch.entity.public_data_cache
        entry = cache._cache.get(issuer_name)
        if not entry or not entry.issuer_data.schema:
            return jsonify(None)
        schema = entry.issuer_data.schema
        user_revealed = [
            k for k in schema.revealed_attributes if k not in _META_KEYS
        ]
        return jsonify({
            "revealed": user_revealed,
            "hidden": schema.hidden_attributes,
            "type": schema.type,
            "context": schema.context,
        })

    # ── Presentation Request Submission ──────────────────────────────

    @app.route("/request-presentation", methods=["POST"])
    def request_submit():
        requested_attributes = request.form.getlist("requested_attributes")

        if not requested_attributes:
            flash("At least one attribute must be selected.", "error")
            return redirect(url_for("request_form"))

        if not state.orch.entity.available:
            flash("Verifier is already awaiting a presentation response.", "error")
            return redirect(url_for("dashboard"))

        # Track what we requested for result enrichment
        state._last_requested_attributes = list(requested_attributes)

        try:
            trail, vp_request = state.orch.send_presentation_request(
                requested_attributes=requested_attributes,
            )
            state.add_trail(trail)

            if trail.status == "COMPLETED":
                flash(
                    f"Presentation request sent. Awaiting Holder response for "
                    f"{len(requested_attributes)} field(s).",
                    "success",
                )
            else:
                flash(f"Request failed: {trail.error}", "error")
        except Exception as e:
            flash(f"Request error: {e}", "error")

        return redirect(url_for("dashboard"))

    # ── API: Verification Results (for polling) ──────────────────────

    @app.route("/api/verification-results")
    def api_verification_results():
        """JSON endpoint for auto-refresh polling."""
        state.check_new_results()
        return jsonify({
            "count": len(state.presentation_results),
            "awaiting": not state.orch.entity.available,
        })

    # ── Start server on daemon thread ────────────────────────────────

    thread = Thread(
        target=app.run,
        kwargs={"host": "0.0.0.0", "port": port, "debug": False},
        daemon=True,
    )
    thread.start()

    return app
