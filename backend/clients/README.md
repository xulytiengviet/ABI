# ABI NEXUS DYELS client

The \`abi_nexus_storage.dl\` file includes Gigahorse's original \`clientlib/storage_modeling/storage_modeling.dl\` and enables .output for existing Datalog relations.

For a checked-out Gigahorse toolchain:

\`\`\`bash
cp backend/clients/abi_nexus_storage.dl /opt/gigahorse-toolchain/clients/
\`\`\`

The backend runs the real analyzer using:

\`\`\`bash
cd /opt/gigahorse-toolchain
uv run ./gigahorse.py -j 1 -T 90 -C clients/abi_nexus_storage.dl /absolute/path/to/contract.hex
\`\`\`

After execution, the normalizer reads relation TSV/CSV files under
\`.temp/<unique-contract-file-stem>/out/\`.
The output path and exact relation CSV format are subject to changes in upstream; the API treats missing outputs as analysis failures, never silently fabricates results.
