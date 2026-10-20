#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Log in to card-authenticating sites in Microsoft Edge, end to end.

Usage:
  python3 scripts/test-browser-edge.py [--url URL [--expect-title TEXT]] ...
                                       [--timeout SECONDS] [--screenshot-dir DIR]

Drives the installed Edge through Playwright (channel "msedge") with a fresh
profile, so no client-certificate decision from an earlier run is reused.
For the run only, the AutoSelectCertificateForUrls policy selects the
card's certificate for each target origin; the previous policy values are
put back on exit. The sites are visited in order in one browser session,
so Windows asks for the card's PIN once, and the user enters it in the
Windows Security dialog: the script never handles a PIN.

Each --url is followed by the part of the title the site gives the page an
authenticated card reaches; a site that answers 401 or 403 did not let the
card in. The page text is never printed, since a logged-in page shows the
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
POLL_SECONDS = 0.5
MILLISECONDS_PER_SECOND = 1000

#: HTTP statuses a site answers when the handshake carried no usable card.
REFUSED_STATUSES = frozenset({401, 403})

POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Edge\AutoSelectCertificateForUrls"


@dataclass(frozen=True)
class Target:
    """One site to log in to and the title that shows it let the card in."""

    url: str
    expected_title: str

    @property
    def origin(self) -> str:
        parts = urlsplit(self.url)
        return f"{parts.scheme}://{parts.netloc}"


class TemporaryCertificatePolicy:
    """Sets AutoSelectCertificateForUrls for the target origins and restores
    the values that were there before."""

    def __init__(self, origins: list[str]) -> None:
        self.rules = [
            json.dumps({"pattern": origin, "filter": {}}, separators=(",", ":"))
            for origin in dict.fromkeys(origins)
        ]
        self.previous: dict[str, tuple[object, int]] = {}

    def __enter__(self) -> TemporaryCertificatePolicy:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, POLICY_KEY, 0, winreg.KEY_ALL_ACCESS) as key:
            for index, rule in enumerate(self.rules, start=1):
                name = str(index)
                try:
                    self.previous[name] = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    pass
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, rule)
        return self

    def __exit__(self, *_exception: object) -> None:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, POLICY_KEY, 0, winreg.KEY_ALL_ACCESS) as key:
            for index in range(1, len(self.rules) + 1):
                name = str(index)
                if name in self.previous:
                    value, kind = self.previous[name]
                    winreg.SetValueEx(key, name, 0, kind, value)
                else:
                    winreg.DeleteValue(key, name)


def log_in(page: Page, target: Target, timeout_seconds: int) -> str:
    """Visits `target` and reports whether it let the card in."""
    statuses: list[int] = []

    def record(response) -> None:
        if response.request.is_navigation_request() and response.frame == page.main_frame:
            statuses.append(response.status)

    page.on("response", record)
    try:
        page.goto(target.url, wait_until="commit", timeout=timeout_seconds * MILLISECONDS_PER_SECOND)
    except PlaywrightError as error:
        page.remove_listener("response", record)
        return f"failed: {error.message.splitlines()[0]}"
    deadline = time.monotonic() + timeout_seconds
    try:
        while time.monotonic() < deadline:
            if statuses and statuses[-1] in REFUSED_STATUSES:
                return f"not logged in: HTTP {statuses[-1]}"
            try:
                if target.expected_title in page.title():
                    return f"logged in: {target.expected_title!r}"
            except PlaywrightError:
                pass
            time.sleep(POLL_SECONDS)
        return f"failed: no outcome within {timeout_seconds} s"
    finally:
        page.remove_listener("response", record)


def run(targets: list[Target], timeout_seconds: int, screenshot_dir: Path | None) -> int:
    outcomes: list[str] = []
    with (
        TemporaryCertificatePolicy([target.origin for target in targets]),
        tempfile.TemporaryDirectory() as profile,
        sync_playwright() as playwright,
    ):
        browser = playwright.chromium.launch_persistent_context(profile, channel="msedge", headless=False)
        try:
            page = browser.new_page()
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
    if all(outcome.startswith("logged in") for outcome in outcomes):
        return EXIT_LOGGED_IN
    if any(outcome.startswith("not logged in") for outcome in outcomes):
        return EXIT_NOT_LOGGED_IN
    return EXIT_FAILED


def parse_targets(arguments: list[str]) -> tuple[list[Target], argparse.Namespace]:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", action="append", default=[], help="a site to log in to")
    parser.add_argument(
        "--expect-title",
        action="append",
        default=[],
        help="part of the title the preceding --url gives an authenticated card's page",
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--screenshot-dir", type=Path, default=None, help="save screenshots here (they show personal data)"
    )
    options = parser.parse_args(arguments)
    urls = options.url or [DEFAULT_URL]
    titles = options.expect_title or ([DEFAULT_EXPECTED_TITLE] if not options.url else [])
    if len(titles) != len(urls):
        parser.error("give one --expect-title for every --url")
    return [Target(url, title) for url, title in zip(urls, titles, strict=True)], options


def main() -> int:
    targets, options = parse_targets(sys.argv[1:])
    return run(targets, options.timeout, options.screenshot_dir)


if __name__ == "__main__":
    sys.exit(main())
