# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Experimental Python library for storing and manipulating sets of CIDR-format IP ranges. Src-layout package: implementation lives in `src/cidr/` (`cidr.py`, re-exported by `__init__.py`), tests in `tests/test_cidr.py`.

## Commands

Dependency/environment management is via `uv`; dev tasks are run through `Taskfile.yml` (go-task).

Install for development:
```
task sync
```

Run tests:
```
task test
```

Run a single test:
```
uv run pytest tests/test_cidr.py::test_name
```

Lint (style checks, max line length 120):
```
task lint
```

Regenerate the trie diagrams in `doc/` (requires Graphviz's `dot`, `gvpr`, and `neato`):
```
task doc
```

## Architecture

- `Cidr` — represents a single CIDR range as a normalized 32-bit integer IP plus a bitmask (0-32). Can be constructed from a string (`"192.168.0.0/24"`) or from explicit `ip`/`bitmask` integers. Bits not covered by the bitmask are always zeroed out on construction. `bit(n)` reads the n-th bit (1-indexed); iterating a `Cidr` yields every individual dotted-quad IP address in the range.
- `CidrSet` — represents a set of (non-overlapping) CIDR ranges as a binary trie built on `binarytree.Node`. Tree depth equals the bitmask value, with `node.left`/`node.right` edges implying a 0/1 bit; a node represents a CIDR if and only if it is a leaf. The full subtree down to depth 32 is implied beneath each leaf.
  - `add()` inserts a CIDR and recursively collapses a parent whose two children are both leaves into a single leaf (since together they cover every value of that bit).
  - `remove()` deletes a CIDR and recursively expands an implied leaf into two explicit child leaves when only part of its range is being removed, propagating deletion upward when a node's children are both removed.
  - `__add__`/`__sub__` implement set union/difference by cloning and replaying `add`/`remove` for each element of the other set.
  - `__iter__` walks the trie (0-edges before 1-edges, tracking the accumulated IP prefix) and yields a `Cidr` at each leaf.

See the "Implementation" section of `README.md` for a diagram-illustrated walkthrough of the collapse/expand behavior (figures generated into `doc/*.svg` via `task doc`).

## Requirements

Python 3.10+ (see `.python-version`). Dependencies and dev/test groups are declared in `pyproject.toml` and pinned in `uv.lock`. Runtime: `binarytree`, plus `setuptools<81` (binarytree imports the now-removed `pkg_resources` API without declaring the dependency itself). Dev group: `pycodestyle==2.10.0`. Test group: `pytest==7.2.1` + `pytest-cov==2.12.1`.
