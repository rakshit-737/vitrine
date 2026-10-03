# CLI and API reference

## Command line

```text
$ vitrine --help
usage: vitrine [-h] [--version] {gen-corpus,train,analyze,scan,serve,demo} ...

VITRINE command-line interface (static analysis only; nothing is ever
executed).

positional arguments:
  {gen-corpus,train,analyze,scan,serve,demo}
    gen-corpus          write synthetic inert PE corpus
    train               train the linear demo model on the synthetic corpus
    analyze             statically analyze a PE file
    scan                triage every PE in a directory (JSON lines)
    serve               run the FastAPI service + triage UI
    demo                end-to-end demo on synthetic samples

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

Each subcommand has its own `--help`. `analyze` and `scan` only read files; nothing is executed. Files over the
parser's 128 MiB cap are skipped before they are read (`scan` reports them as `too large`). Analysis keeps the
file and several derived copies (strings, byte histograms, feature blocks) in memory, so peak memory is a large
multiple of the file size; scan very large installers one at a time.

## HTTP API (`vitrine serve`)

| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| GET | `/health` | none | status, version, model type, benign corpus size |
| GET | `/api/model` | none | model type, calibrated thresholds, metadata, known families |
| POST | `/api/analyze` | raw PE bytes (`application/octet-stream`, at most 32 MB) | full triage result (verdict, score, SHAP drivers, capabilities, YARA rule) |
| POST | `/api/yara/validate` | `{"text": "<rule>"}` | benign hits and specificity against the configured benign corpus |

The OpenAPI schema is at `/openapi.json`. The interactive `/docs` page (Swagger UI, loaded from a CDN) is served
only with `vitrine serve --enable-docs`; `/redoc` is off. At most two uploads are buffered and analysed at once
(further requests wait unread), which bounds the service's memory. A static, server-less copy of the UI is on the
[demo page](demo/index.html).

## Python API

::: vitrine.triage
    options:
      members: [analyze, load_model, train_default]

::: vitrine.dissect
    options:
      members: [dissect, PEParseError]

::: vitrine.gbdt.GBDTVerdictModel

::: vitrine.yara_synth
    options:
      members: [synthesize, validate, match, parse]

::: vitrine.capabilities
