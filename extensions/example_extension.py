"""Minimal local extension example for KCONK Suite."""

NAME = "Example Extension"
VERSION = "1.0"


def register(app):
    app.log_event(f"Loaded extension: {NAME} v{VERSION}")
