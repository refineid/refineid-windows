#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Log in to card-authenticating sites in Microsoft Edge, end to end.

Usage:
  python3 scripts/test-browser-edge.py [--url URL [--expect-title TEXT]] ...
                                       [--timeout SECONDS] [--screenshot-dir DIR]

Drives the installed Edge through Playwright (channel "msedge") with a fresh
profile, so no client-certificate decision from an earlier run is reused.
For the run only, the AutoSelectCertificateForUrls policy holds exactly one
rule per target origin, selecting the card's certificate; the values the
policy held before are put back on exit. The sites are visited in order in
one browser session, so Windows asks for the card's PIN once, and the user
enters it in the Windows Security dialog: the script never handles a PIN.

A site that answers 401 or 403 did not let the card in. A site given an
--expect-title let the card in when the loaded page's title contains that
text; one without lets it in when its page loads with any other status.
The page text is never printed, since a logged-in page shows the
cardholder's name and identity number. Screenshots, which show them too,
are saved only to a directory the caller names.

Requirements: Python 3 with the playwright package, the RefineID card
module installed, and a card in a reader.

Exit status: 0 every site logged in, 2 a site answered without a login,
1 any other failure.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import winreg
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, sync_playwright

EXIT_LOGGED_IN = 0
EXIT_FAILED = 1
EXIT_NOT_LOGGED_IN = 2

DEFAULT_URL = "https://card.refineid.fi"
#: The title card.refineid.fi gives the page it serves to an authenticated card.
DEFAULT_EXPECTED_TITLE = "Card-authenticated guestbook"
DEFAULT_TIMEOUT_SECONDS = 90
MILLISECONDS_PER_SECOND = 1000

#: HTTP statuses a site answers when the handshake carried no usable card.
REFUSED_STATUSES = frozenset({401, 403})

POLICY_PARENT_KEY = r"SOFTWARE\Policies\Microsoft\Edge"
POLICY_SUBKEY = "AutoSelectCertificateForUrls"
POLICY_KEY = rf"{POLICY_PARENT_KEY}\{POLICY_SUBKEY}"
POLICY_ACCESS = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE


@dataclass(frozen=True)
class Target:
    """One site to log in to, and the title that shows it let the card in."""

    url: str
    expected_title: str | None

    @property
    def origin(self) -> str:
        parts = urlsplit(self.url)
        return f"{parts.scheme}://{parts.netloc}"


@dataclass(frozen=True)
class Outcome:
    """What one site did with the card."""

    logged_in: bool
    refused: bool
    detail: str

    def __str__(self) -> str:
        if self.logged_in:
            return f"logged in: {self.detail}"
        if self.refused:
            return f"not logged in: {self.detail}"
        return f"failed: {self.detail}"


class TemporaryCertificatePolicy:
    """Gives AutoSelectCertificateForUrls exactly one rule per target origin
    for the run, and puts back every value it held before. A key the run
    created is deleted again."""

    def __init__(self, origins: list[str]) -> None:
        self.rules = [
            json.dumps({"pattern": origin, "filter": {}}, separators=(",", ":"))
            for origin in dict.fromkeys(origins)
        ]
        self.previous: list[tuple[str, object, int]] = []
        self.created = False

    def __enter__(self) -> TemporaryCertificatePolicy:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, POLICY_KEY, 0, POLICY_ACCESS)
        except FileNotFoundError:
            key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, POLICY_KEY, 0, POLICY_ACCESS)
            self.created = True
        with key:
            self.previous = self._values(key)
            for name, _value, _kind in self.previous:
                winreg.DeleteValue(key, name)
            for index, rule in enumerate(self.rules, start=1):
                winreg.SetValueEx(key, str(index), 0, winreg.REG_SZ, rule)
        return self

    def __exit__(self, *_exception: object) -> None:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, POLICY_KEY, 0, POLICY_ACCESS) as key:
            for name, _value, _kind in self._values(key):
                winreg.DeleteValue(key, name)
            for name, value, kind in self.previous:
                winreg.SetValueEx(key, name, 0, kind, value)
        if self.created:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, POLICY_PARENT_KEY, 0, POLICY_ACCESS) as parent:
                winreg.DeleteKey(parent, POLICY_SUBKEY)

    @staticmethod
    def _values(key: winreg.HKEYType) -> list[tuple[str, object, int]]:
        values = []
        index = 0
        while True:
            try:
                values.append(winreg.EnumValue(key, index))
            except OSError:
                return values
            index += 1


def log_in(page: Page, target: Target, timeout_seconds: int) -> Outcome:
    """Visits `target` within `timeout_seconds`, the PIN entry included, and
    reports what it did with the card."""
    deadline = time.monotonic() + timeout_seconds
    statuses: list[int] = []

    def record(response) -> None:
        if response.request.is_navigation_request() and response.frame == page.main_frame:
            statuses.append(response.status)

    def remaining_ms() -> float:
        return max(0.0, deadline - time.monotonic()) * MILLISECONDS_PER_SECOND

    page.on("response", record)
    try:
        page.goto(target.url, wait_until="load", timeout=remaining_ms())
        status = statuses[-1] if statuses else None
        if status in REFUSED_STATUSES:
            return Outcome(logged_in=False, refused=True, detail=f"HTTP {status}")
        if target.expected_title is None:
            return Outcome(logged_in=True, refused=False, detail=f"HTTP {status}")
        title = page.title()
        if target.expected_title in title:
            return Outcome(logged_in=True, refused=False, detail=repr(target.expected_title))
        return Outcome(
            logged_in=False,
            refused=True,
            detail=f"HTTP {status}, the page title lacks {target.expected_title!r}",
        )
    except PlaywrightError as error:
        return Outcome(logged_in=False, refused=False, detail=error.message.splitlines()[0])
    finally:
        page.remove_listener("response", record)


def run(targets: list[Target], timeout_seconds: int, screenshot_dir: Path | None) -> int:
    outcomes: list[Outcome] = []
    with (
        TemporaryCertificatePolicy([target.origin for target in targets]),
        tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as profile,
        sync_playwright() as playwright,
    ):
        browser = playwright.chromium.launch_persistent_context(profile, channel="msedge", headless=False)
        try:
            page = browser.pages[0] if browser.pages else browser.new_page()
            print("enter the card PIN in the Windows Security dialog when Windows asks for it")
            for index, target in enumerate(targets, start=1):
                outcome = log_in(page, target, timeout_seconds)
                outcomes.append(outcome)
                print(f"{target.origin}: {outcome}")
                if screenshot_dir:
                    screenshot_dir.mkdir(parents=True, exist_ok=True)
                    path = screenshot_dir / f"edge-login-{index}.png"
                    page.screenshot(path=str(path))
                    print(f"  screenshot saved to {path}")
        finally:
            browser.close()
    if all(outcome.logged_in for outcome in outcomes):
        return EXIT_LOGGED_IN
    if any(outcome.refused for outcome in outcomes):
        return EXIT_NOT_LOGGED_IN
    return EXIT_FAILED


def parse_targets(arguments: list[str]) -> tuple[list[Target], argparse.Namespace]:
    """Pairs each --url with the --expect-title that follows it, if any."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--screenshot-dir", type=Path, default=None, help="save screenshots here (they show personal data)"
    )
    options, rest = parser.parse_known_args(arguments)
    targets: list[Target] = []
    cursor = iter(rest)
    for flag in cursor:
        value = next(cursor, None)
        if value is None:
            parser.error(f"{flag} needs a value")
        if flag == "--url":
            targets.append(Target(value, None))
        elif flag == "--expect-title" and targets and targets[-1].expected_title is None:
            targets[-1] = Target(targets[-1].url, value)
        elif flag == "--expect-title":
            parser.error("--expect-title follows the --url it belongs to")
        else:
            parser.error(f"unknown argument {flag}")
    return targets or [Target(DEFAULT_URL, DEFAULT_EXPECTED_TITLE)], options


def main() -> int:
    targets, options = parse_targets(sys.argv[1:])
    return run(targets, options.timeout, options.screenshot_dir)


if __name__ == "__main__":
    sys.exit(main())
