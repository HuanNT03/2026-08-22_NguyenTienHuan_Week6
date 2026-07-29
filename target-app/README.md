# Pinned target application

`juice-shop/` is generated locally by cloning the repository and revision recorded in
`TARGET.lock`. Its source is intentionally excluded from this Sentinel repository.

Do not modify files inside `juice-shop/`. Create or verify the target with:

```bash
make setup-target
make verify-target
```

If the directory already exists, setup only verifies it and never resets or replaces it.
To download a fresh copy, run `make clean` followed by `make setup-target`.
