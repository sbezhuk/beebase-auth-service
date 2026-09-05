-- RFC 6238 §5.2 anti-replay: the RFC 6238 time-step counter of the most
-- recently accepted TOTP code, so that step (or any earlier one) can never
-- authenticate again. NULL until the credential's first successful
-- verification. Without this, a code captured by an attacker (e.g. via
-- shoulder-surfing or network interception) stays usable for as long as
-- the validation skew window tolerates it, even after the legitimate user
-- has already used it - see BEEB-41.
ALTER TABLE two_factor_credentials
    ADD COLUMN last_used_totp_counter BIGINT;
