# SRS OPAQUE

This is an implementation of the [OPAQUE protocol](1) for [SRS](2).

This library is heavily influnced by [opaque-ke](3) with the following
differences:

- We use a threshold-POPRF protocol over the BLS12-381 curve and use
  Shmair's Secret Sharing to split OPRF's secret key across servers.
- We add a payload to the registration record that allows the user to
  store the configuration for the key-stretching function (KSF), e.g.,
  [Argon2](4).

[1]: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-11.html
[2]: https://github.com/blockshake-io/srs
[3]: https://github.com/facebook/opaque-ke
[4]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id