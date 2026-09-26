# ADR 0006: A single-file vanilla-JS triage UI instead of a React app

- Status: accepted
- Date: 2026-09-26

## Context

The spec lists React for the analyst UI. The UI has one job: upload a file, then show the
verdict, the drivers, the capabilities and an editable rule.

## Decision

`vitrine/static/index.html` is one self-contained page served by FastAPI. It has no build step,
no npm dependency tree and no CDN, so it works offline in an air-gapped lab VM. It follows the
light/dark system theme and posts the file bytes as `application/octet-stream`, which avoids a
multipart dependency.

## Consequences

It is fine for a single analyst. A multi-user case-management UI would warrant a real frontend
stack, and that is on the roadmap.
