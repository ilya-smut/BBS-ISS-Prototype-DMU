"""
Flask UI application for the Registry entity.

Provides a browser-based interface for inspecting and
managing registered issuer records.
"""

import os
from threading import Thread

from flask import Flask, render_template, redirect, url_for, flash

from bbs_iss.endpoints.orchestrator import RegistryOrchestrator


def create_registry_ui(orch: RegistryOrchestrator, port: int = 8001) -> Flask:
    """
    Create and start the Registry UI Flask application.

    Parameters
    ----------
    orch : RegistryOrchestrator
        The orchestrator returned by registry_bootstrap().
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

    # ── Dashboard ────────────────────────────────────────────────────

    @app.route("/")
    def dashboard():
        store = orch.entity._store
        records = []
        for name, data in store.items():
            pk_hex = data.public_key.key.hex()
            schema = data.schema
            records.append({
                "name": name,
                "pk_short": f"{pk_hex[:10]}...{pk_hex[-10:]}",
                "pk_full": pk_hex,
                "bitstring": data.revocation_bitstring,
                "bitstring_bits": len(data.revocation_bitstring) * 4,
                "epoch_days": data.epoch_size_days,
                "reissue_window_days": data.validity_window_days,
                "schema_type": schema.type if schema else None,
                "schema_context": schema.context if schema else None,
                "schema_revealed": schema.revealed_attributes if schema else [],
                "schema_hidden": schema.hidden_attributes if schema else [],
            })
        return render_template("dashboard.html", records=records)

    # ── Delete Record ────────────────────────────────────────────────

    @app.route("/delete/<issuer_name>", methods=["POST"])
    def delete_record(issuer_name):
        store = orch.entity._store
        if issuer_name in store:
            del store[issuer_name]
            flash(f"Record '{issuer_name}' deleted.", "success")
        else:
            flash(f"Record '{issuer_name}' not found.", "error")
        return redirect(url_for("dashboard"))

    # ── Start server on daemon thread ────────────────────────────────

    thread = Thread(
        target=app.run,
        kwargs={"host": "0.0.0.0", "port": port, "debug": False},
        daemon=True,
    )
    thread.start()

    return app
