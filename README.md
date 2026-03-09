# Intezer Analyze — Binary Ninja Plugin

Fetches gene/block-level intelligence from [Intezer Analyze](https://analyze.intezer.com) and annotates the current binary with software-type labels, code-reuse info, and inline comments.

## Setup

```bash
export INTEZER_API_KEY=<your key>
# Optional: export INTEZER_BASE_URL=https://your-intezer-instance.com
```

Install by placing this directory in your Binary Ninja plugins folder:

```
~/.binaryninja/plugins/intezer/
```

## Usage

**Tools → Intezer → Fetch Intezer Gene Data**

The plugin will:
1. Compute the SHA-256 of the open binary
2. Query Intezer Analyze for block-level gene data
3. Annotate functions and basic blocks with reuse labels and comments
4. Export results to CSV
5. Open a results panel in the GUI

## Files

| File | Purpose |
|------|---------|
| `__init__.py` | Plugin entry point, command registration |
| `api.py` | Intezer REST API client |
| `analysis.py` | Block map construction, comment injection, CSV export |
| `ui.py` | Binary Ninja results panel widget |

## Requirements

- Binary Ninja (with Python plugin support)
- Intezer Analyze API key

## To Do
- [ ] Use the Intezer SDK, such as in https://github.com/intezer/malcat
