# Function Address Recovery Benchmark

Comparative benchmark of function address recovery from stripped ELF binaries, evaluating four tools across 85,652 ground truth functions from ten production binaries.

Supporting material for the doctoral thesis *"Beyond Reachability: Cross-Architecture Binary Libification and Procedural Debugging for Vulnerability Assessment"* (CNAM/CEDRIC, 2026).

## Results

Aggregate metrics across 85,652 ground truth function addresses from Ubuntu 24.04 LTS production binaries:

| Tool | Method | Precision | Recall | F1 | TP | FP | FN |
|------|--------|-----------|--------|------|--------|---------|--------|
| **wunstrip** | `.eh_frame` (deterministic) | **100.00%** | **99.93%** | **99.96%** | 85,592 | 2 | 60 |
| Ghidra 11.3.2 | CFG + heuristics | 88.51% | 99.47% | 93.67% | 85,196 | 11,062 | 456 |
| radare2 | `aaa` analysis | 99.66% | 62.37% | 76.73% | 53,422 | 180 | 32,230 |
| angr | CFGFast | 22.98% | 89.74% | 36.59% | 76,865 | 257,639 | 8,787 |

### Per-Binary Breakdown

| Binary | Domain | GT | wunstrip F1 | Ghidra F1 | radare2 F1 | angr F1 |
|--------|--------|----|-------------|-----------|------------|---------|
| vlc | Media Player | 15 | 75.0% | 96.6% | 66.7% | 65.1% |
| smbd | File Server | 48 | 93.3% | 97.9% | 49.2% | 42.7% |
| ls | Core Utility | 191 | 98.4% | 99.2% | 65.1% | 35.0% |
| liblzma | Compression | 328 | 99.1% | 98.8% | 71.1% | 36.4% |
| libjpeg | Image Library | 369 | 99.2% | 99.3% | 65.6% | 42.1% |
| sshd | SSH Daemon | 834 | 99.6% | 99.6% | 84.0% | 35.3% |
| nginx | Web Server | 1,663 | 99.8% | 99.7% | 65.1% | 31.8% |
| proftpd | FTP Server | 2,001 | 99.8% | 98.9% | 83.0% | 35.8% |
| postgres | Database | 18,324 | 100.0% | 95.7% | 83.0% | 37.8% |
| mysqld | Database | 61,879 | 100.0% | 92.6% | 74.8% | 36.5% |

## Key Findings

**wunstrip** achieves simultaneous near-perfect precision and recall through deterministic `.eh_frame` parsing. The 2 false positives on PostgreSQL result from weak symbol aliasing (multiple symbol names at the same address, [documented in wcc-tests-wunstrip](https://github.com/endrazine/wcc-tests-wunstrip)). The constant 6 false negatives per binary are compiler runtime functions (`_init`, `_fini`, `__do_global_dtors_aux`, `register_tm_clones`, `deregister_tm_clones`, `frame_dummy`) not covered by `.eh_frame` FDEs but recovered by complementary section header analysis and pattern fingerprinting in the full multi-method framework.

**Ghidra** is the strongest heuristic competitor with excellent recall (99.47%) but generates 11,062 false positives from heuristic misidentification of data as code, particularly on large binaries (9,665 FP on mysqld, 1,384 FP on postgres).

**radare2** takes the opposite tradeoff: extremely precise (99.66%, only 180 FP total) but conservative, missing 37.63% of all functions. Its heuristic analysis only reports functions it is confident about.

**angr** achieves decent recall (89.74%) but catastrophic precision (22.98%), producing 257,639 false positives — three times more phantom functions than real ones exist. This results from CFGFast's aggressive recovery treating data as code.

## Test Corpus

Ten production binaries from Ubuntu 24.04 LTS, stripped with modern mitigations enabled:

| Binary | Path | Functions | PIE | RELRO |
|--------|------|-----------|-----|-------|
| vlc | `/usr/bin/vlc` | 15 | Yes | Full |
| smbd | `/usr/sbin/smbd` | 48 | Yes | Full |
| ls | `/bin/ls` | 191 | Yes | Full |
| liblzma.so.5 | `/lib/x86_64-linux-gnu/liblzma.so.5` | 328 | N/A | Full |
| libjpeg.so.9.5.0 | `/lib/x86_64-linux-gnu/libjpeg.so.9.5.0` | 369 | N/A | Partial |
| sshd | `/usr/sbin/sshd` | 834 | Yes | Full |
| nginx | `/usr/sbin/nginx` | 1,663 | Yes | Full |
| proftpd | `/usr/sbin/proftpd` | 2,001 | Yes | Full |
| postgres | `/usr/lib/postgresql/16/bin/postgres` | 18,324 | Yes | Full |
| mysqld | `/usr/sbin/mysqld` | 61,879 | Yes | Full |

**Total**: 85,652 functions across four orders of magnitude.

## Methodology

### Ground Truth

Ground truth function addresses are established via Ubuntu's [debuginfod](https://wiki.ubuntu.com/Debug%20Symbol%20Packages) infrastructure, which provides cryptographically-verified debug symbols matched by Build-ID. These are merged with stripped binaries using `wunstrip -d`, then function addresses extracted via `nm`:

```bash
# Fetch and merge debug symbols
wunstrip binary -d -o binary.dbg

# Extract all text section function addresses
nm binary.dbg | grep -E '\b[tT]\b' | awk '{print $1}' | sort -u
```

### Address-Based Validation

Comparison is performed on **function start addresses**, not symbol names. This is the security-critical metric: vulnerability assessment and binary libification require code locations, not names. Multiple symbol names may alias to the same address (weak symbols), making name-based comparison unreliable.

### Tool Configuration

- **wunstrip**: `.eh_frame` FDE/CIE parsing via `wunstrip -e -R` (deterministic, no heuristics)
- **Ghidra 11.3.2**: `analyzeHeadless` with default analysis, addresses normalized by subtracting `ImageBase` (PIE binaries are loaded at 0x100000), PLT/thunk/external functions filtered
- **radare2**: `aaa` full analysis, function list via `aflj`, `sym.imp.*` PLT stubs filtered
- **angr**: `CFGFast(normalize=True, force_complete_scan=False)`, addresses normalized by subtracting `mapped_base` (PIE binaries loaded at 0x400000), PLT/SimProcedure/external functions filtered

### PIE Address Normalization

Position-Independent Executables (PIE) are loaded at different base addresses by each analysis tool: Ghidra at `0x100000`, angr at `0x400000`, while `nm` on debug symbol files reports original ELF addresses (typically `0x0`-based for PIE). All addresses are normalized to the original ELF virtual address space before comparison by subtracting each tool's image base offset. Without this normalization, address sets are incomparable and all comparisons show 0% match.

### PLT Filtering

Procedure Linkage Table (PLT) stubs are trampolines to shared library functions, generated by the linker. They are not application code and are not present in the ground truth (debug symbols do not contain PLT entries). All tools' output is filtered to exclude PLT entries for a fair comparison.

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- x86_64 host system
- 16 GB RAM, 10 GB disk space
- Internet connection (for Docker image pull and Ghidra download)

### Build & Run

```bash
git clone https://github.com/endrazine/wcc-tests-wunstrip-benchmark
cd wcc-tests-wunstrip-benchmark
make build    # Build Docker image (~2 minutes)
make results  # Run benchmark and extract results (~2-4 hours)
```

Results are extracted to:
- `./comparison_results.json` — full per-binary, per-tool metrics
- `./wunstrip_benchmark_table.tex` — LaTeX table for thesis integration
- `./results/` — raw address files for each tool × binary

### Interactive Mode

```bash
make run   # Drop into container shell
bash /root/run_benchmark.sh   # Run benchmark manually
```

## Docker Image

The benchmark extends [`endrazine/wcc-tests-unstrip:latest`](https://hub.docker.com/r/endrazine/wcc-tests-unstrip) from DockerHub, which already contains:

- Ubuntu 24.04 LTS base system
- Witchcraft Compiler Collection (WCC) with `wunstrip`
- All 10 test binaries pre-installed
- Pre-computed debug symbols (`.dbg`) and wunstrip results (`.unstripped`)

The benchmark Dockerfile adds:
- **Ghidra 11.3.2** (headless analysis mode)
- **radare2** (from Ubuntu repositories)
- **angr** (Python virtual environment)

## File Structure

```
├── Dockerfile                  # Extends wcc-tests-unstrip with Ghidra, r2, angr
├── Makefile                    # build / run / results / clean targets
├── run_benchmark.sh            # Orchestrates all 4 tools on all 10 binaries
├── ghidra_extract.py           # Ghidra Jython post-analysis script
├── angr_extract.py             # angr CFGFast extraction script
├── compare_tools.py            # Computes TP/FP/FN/P/R/F1, generates JSON + LaTeX
├── comparison_results.json     # Full per-binary, per-tool metrics
├── wunstrip_benchmark_table.tex # LaTeX table for thesis integration
└── results/                    # Raw results per binary
    └── <binary>/
        ├── ground_truth.txt    # Ground truth addresses from debuginfod symbols
        ├── wunstrip_addrs.txt  # Addresses recovered by wunstrip
        ├── ghidra_addrs.txt    # Addresses recovered by Ghidra
        ├── r2_addrs.txt        # Addresses recovered by radare2
        ├── angr_addrs.txt      # Addresses recovered by angr
        ├── ghidra.log          # Ghidra analysis log
        ├── angr.log            # angr analysis log
        └── r2_filter.log       # radare2 PLT filter log
```

The raw address files enable independent verification: each file contains one hexadecimal function address per line, sorted. The ELF binaries themselves (stripped, `.dbg`, `.unstripped`) are not included in the repository as they are available from the Docker image and Ubuntu repositories.

## Citation

If using this benchmark in academic research:

```bibtex
@software{brossard2026wunstrip_benchmark,
  author       = {Brossard, Jonathan},
  title        = {Function Address Recovery Benchmark: wunstrip vs Ghidra vs radare2 vs angr},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.24242625},
  url          = {https://doi.org/10.5281/zenodo.24242625}
}
```

## Related Resources

- [Witchcraft Compiler Collection](https://github.com/endrazine/wcc) — Main WCC framework
- [wcc-tests-wunstrip](https://github.com/endrazine/wcc-tests-wunstrip) — wunstrip validation framework
- [wcc-tests-unstrip DockerHub](https://hub.docker.com/r/endrazine/wcc-tests-unstrip) — Base Docker image

## License

Dual MIT/BSD License (consistent with WCC framework)

Permanent Archive: https://doi.org/10.5281/zenodo.24242625
