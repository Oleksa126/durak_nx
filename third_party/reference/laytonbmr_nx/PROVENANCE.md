# Architectural Reference Provenance: laytonbmr_nx

This document records the provenance, upstream snapshot, licensing, and clean separation boundaries for the `laytonbmr_nx` architectural reference project as mandated by Milestone M0 / E01.

---

## 1. Upstream Metadata

- **Repository:** `https://github.com/NaGaa95/laytonbmr_nx`
- **Author:** NaGaa95
- **Upstream Tag / Release:** `1.0.1` (commit `5763d239f03e57447832bcb1450a3ac1099846c7`, 2026-07-15)
- **License:** MIT License (SPDX: `MIT`)

---

## 2. Architectural Role vs. Game-Specific Boundaries

`laytonbmr_nx` serves strictly as a high-level architectural reference for:
1. General patterns for hosting ARM64 Android ELF shared libraries under Horizon OS.
2. Minimal Bionic libc/libm shimming approaches.
3. Unity lifecycle initialization patterns (`Unity_nativeRender`, `ANativeWindow` glue).

### Strict Negative Boundaries (Fail-Closed Policy):
- **Zero Game Code:** None of Layton Brothers Mystery Room's game-specific code, RVAs, patch points, or data structures are included or used in Durak NX.
- **Independent Analysis:** All Durak 25.0 RVAs, patch sites, and IL2CPP metadata v39 structures are extracted directly from the verified Android APK (`ru.appscraft.durak` 25.0) via `tools/durak_analyzer.py` and validated by fail-closed unit tests.
- **Separation of Directories:**
  * `source/`, `include/`: Proprietary port production code written specifically for Durak NX.
  * `third_party/reference/`: Architectural reference documents and licensing disclosures only.
  * `tools/`: Host analysis, ELF extraction, and verification tools.
  * `extracted_durak/`: Extracted target binaries from the user's legally acquired APK (git-ignored).
