#!/usr/bin/env python3
"""Compatibility wrapper for the renamed desktop agent."""

from ironkey_vp50_desktop_agent import main


if __name__ == "__main__":
    raise SystemExit(main())
