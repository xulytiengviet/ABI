# ABI NEXUS · Gigahorse–DYELS backend (v0.2)

This is a **real analyzer adapter** for the open-source Gigahorse storage-modeling (DYELS) library. It does not return simulated results. If Gigahorse, Soufflé or its Datalog output are unavailable, it returns HTTP 503/502 instead of inventing storage slots.

## 1. Requirements

- Linux host/container that can run upstream Gigahorse.
- CPython 3.10+ for this API, uv and an upstream Gigahorse-compatible Python installed by uv.
- Soufflé and Gigahorse native functors (Boost and Z3), configured per upstream instructions.
- Enough RAM/CPU for analysis. The target bytecode limit is **175 KB**; analysis is serialized.
- HTTPS reverse proxy when serving users on GitHub Pages.

Upstream toolchain: https://github.com/nevillegrech/gigahorse-toolchain
Storage modeling API: https://github.com/nevillegrech/gigahorse-toolchain/tree/master/clientlib/storage_modeling

### Install Gigahorse

Follow upstream README.md for compatible Python / uv, Soufflé, Boost and Z3 versions. These commands assume Gigahorse has already been built and can run on the provided test contract:

    git clone --recursive https://github.com/nevillegrech/gigahorse-toolchain.git /opt/gigahorse-toolchain
    cd /opt/gigahorse-toolchain
    uv sync
    # Complete Soufflé and custom functors setup per upstream README.
    uv run ./gigahorse.py examples/long_running.hex

Gigahorse is a research toolchain. Compile/test it independently first. Pin an upstream commit SHA for reproducible production builds.

Copy our actual Datalog export client into the Gigahorse clients directory:

    cp /path/to/ABI/backend/clients/abi_nexus_storage.dl /opt/gigahorse-toolchain/clients/abi_nexus_storage.dl

It includes the original storage_modeling.dl library and exposes:
- StorageVariableInfo
- StorageVariable_Type
- DataStructure_Type
- Mapping_KeyType
- DataStructure_ValueOrElementType
- DataStructureValueIsStruct
- StorageStmtKindAndConstruct
- StorageStmt_HighLevelUses

## 2. Start the API

    cd /path/to/ABI/backend
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt

    export GIGAHORSE_HOME=/opt/gigahorse-toolchain
    export ABI_ALLOWED_ORIGINS='https://xulytiengviet.github.io,http://localhost:8000'
    export ABI_ANALYSIS_TIMEOUT=110
    # Optional; recommended for restricted environments:
    export ABI_API_KEY='a-high-entropy-value'
    .venv/bin/uvicorn api:app --host 127.0.0.1 --port 8787

The FastAPI service is not deployed to GitHub Pages. Expose it through a dedicated HTTPS reverse proxy with server-side authorization/Cloudflare Access, rate limits, CPU/memory constraints and filesystem permissions before public use. The frontend sends a bearer token only when explicitly supplied in the form; never embed a private API key in public JS.

## 3. API

GET /api/health returns engine, dyelsReady and version. A ready response means basic binaries and paths exist, not that a complete contract test has passed.

POST /api/analyze (Content-Type: application/json)

    {"bytecode":"0x60005400"}

Successful response: engine = gigahorse-dyels, slots, mappings, relations, warnings, relationCounts. Mapping keys/value may remain unknown when Datalog provides insufficient evidence.

Error codes: 401 unauthorized (if configured), 422/413 bad bytecode, 429 busy, 503 unavailable, 502 upstream failure/no relations, 504 timeout.

    curl http://127.0.0.1:8787/api/health
    curl -X POST http://127.0.0.1:8787/api/analyze -H 'Content-Type: application/json' --data '{"bytecode":"0x60005400"}'

Add Authorization: Bearer with your token if configured.

## 4. Important limitations

- Datalog relations are read as Soufflé tab-separated .csv outputs from Gigahorse's .temp/<contract>/out directory. Upstream changes may require adaptation.
- The adapter is **unit-tested with synthetic relation fixtures**, but end-to-end DYELS results on an actual deployed server need independent verification once the native toolchain is installed. No backend deployment is included here.
- Jobs are serialized because Gigahorse may write shared state, each with unique input and bounded timeout.
- A TightlyPackedVariable relation is represented with byte offset and width; an overlap is flagged as observed, never definitively labeled a storage collision.
- Mapping_KeyType and DataStructure_ValueOrElementType are joined by storage root and construct depth. If upstream changes its ADT representation, update the normalizer and fixtures.
- Only runtime EVM bytecode is accepted. For proxy/UUPS, analyze proxy and implementation separately and record storage ownership.
- The service never claims to recover original Solidity source; no private key or transaction signing is supported.
