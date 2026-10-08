# Project boundaries

- This is a metadata catalog, not a query engine. Keep the server independent of
  OrchidDB, Arrow, DataFusion, and provider SDKs. Use JSON Schema for registrations.
- Keep it in Rust with asynchronous HTTP. Support SQLite and PostgreSQL through
  the same storage contract; do not introduce extra services for routine features.
- Preserve immutable published releases. Apply current grants to historical reads.
- Validate structural relationships here; query binding, provider capabilities,
  data authorization, credentials, and execution belong to the consuming engine.
- Run tests locally. Exercise both database backends when PostgreSQL is available.
