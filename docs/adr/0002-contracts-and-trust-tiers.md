# ADR 0002: contracts carry trust tiers
- Status: accepted.
- Each column in `contracts/*.yaml` declares a tier: TRUSTED, STRUCTURED (bounded: anchored regex of width <= 16, or <= 64 char accepted values, or typed) or UNTRUSTED (free text).
- Landing tests enforce the bounds; the library rejects loose regexes (`check_regex_bound`) at load time.
- Promotions are only UNTRUSTED -> STRUCTURED through named validators (`typed_cast`, `literal_choice`); never to TRUSTED. Details: ADR 0004.
