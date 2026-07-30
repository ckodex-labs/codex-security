"""Exact command dispatch for the Codex Security workbench facade."""

from __future__ import annotations

import argparse
import sqlite3
from collections.abc import Callable, Mapping
from typing import Any

CommandHandler = Callable[[sqlite3.Connection, argparse.Namespace], dict[str, Any]]


def dispatch(
    command: str,
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    handlers: Mapping[str, CommandHandler],
) -> dict[str, Any]:
    handler = handlers.get(command)
    if handler is None:
        raise SystemExit(f"Unknown command: {command}")
    return handler(connection, args)


def registered_commands(handlers: Mapping[str, CommandHandler]) -> tuple[str, ...]:
    return tuple(sorted(handlers))
