# CISA KEV source contract (planned)

**Source:** CISA Known Exploited Vulnerabilities catalog. Official repository: https://github.com/cisagov/kev-data . Reference schema: https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json . The implementation must retrieve and validate the *current* official schema rather than assuming fields are immutable.

## Source semantics

One entry represents a CVE listed in a selected published KEV catalog snapshot, not one observed exploitation event. `dateAdded` is the date CISA added the entry; it is **not** the date of initial exploitation. A `dueDate` refers to the applicable federal remediation directive, not a universal organizational deadline. A ransomware-use value of `Unknown` is not `No`.

## Expected catalog elements (verify against downloaded schema)

- Catalog metadata, including version/release information and any declared vulnerability count.
- Per-record `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, and `knownRansomwareCampaignUse` where specified by the schema.
- Optional fields must stay nullable. Store the original source payload; do not silently invent missing attributes.

## Validation gates

- JSON must parse and satisfy the official JSON Schema that matches the downloaded catalog.
- `cveID` must be a normalized, valid full identifier; no duplicate CVE IDs within a snapshot.
- Validate required fields and date syntax. Catalog-declared count must reconcile with parsed entries; a mismatch blocks publication.
- Preserve original values and reported metadata. Store all validation failures with a clear failure reason.

## Snapshot identity

Record: source URL, downloaded-at UTC, SHA-256 of original bytes, file size, catalog release/version metadata, parser version, record count, and resulting immutable snapshot ID. Identical downloaded content must not create another distinct snapshot.

## Analytical restrictions

Use the KEV population for vendor/product-based analyses. A current KEV listing is evidence of catalog membership, not proof of the exploitability or exposure of any particular organization. Historical membership inferred from today's catalog plus `dateAdded` must be labeled **reconstructed**, not represented as a historical original snapshot.
