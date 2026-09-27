# Changelog

## [0.9.1](https://github.com/osanderson/singpass-client-go/compare/v0.9.0...v0.9.1) (2026-09-27)


### Documentation

* bring docs up to date with v0.8–v0.9 changes ([#52](https://github.com/osanderson/singpass-client-go/issues/52)) ([d69b415](https://github.com/osanderson/singpass-client-go/commit/d69b4154f365baaca1cac144cb31d6a9fb594a2b))

## [0.9.0](https://github.com/osanderson/singpass-client-go/compare/v0.8.0...v0.9.0) (2026-09-27)


### ⚠ BREAKING CHANGES

* Client.Complete and web.Authenticator.Complete take the login's state (from BeginLogin, kept with the browser) as a third argument; and under AssuranceProduction, set Dependencies.KeyCustody to KeyCustody{Durable: true} and leave Dependencies.Random unset (crypto/rand.Reader).

### Features

* expose Singpass error codes, bind callbacks to the browser, declare key custody ([f4eb576](https://github.com/osanderson/singpass-client-go/commit/f4eb57614dca52a80872abde0729bfb7acb38aa7))


### Bug Fixes

* **deps:** update FAPIgo to v0.38.0 ([#49](https://github.com/osanderson/singpass-client-go/issues/49)) ([3e830ca](https://github.com/osanderson/singpass-client-go/commit/3e830cab7d2debdcae3d7b00fbb52d67011275b2))
* **myinfo:** zero-pad a one-digit floor in formatted addresses ([#51](https://github.com/osanderson/singpass-client-go/issues/51)) ([02cfe40](https://github.com/osanderson/singpass-client-go/commit/02cfe40b67104231987a25cf1872b154cc1db9a7))

## [0.8.0](https://github.com/osanderson/singpass-client-go/compare/v0.7.0...v0.8.0) (2026-09-27)


### Features

* support key rotation without downtime ([#42](https://github.com/osanderson/singpass-client-go/issues/42)) ([0293f31](https://github.com/osanderson/singpass-client-go/commit/0293f31f46f372f8d9e60756c8dbdb34a954973e))
* validate options up front and check the published JWKS ([#40](https://github.com/osanderson/singpass-client-go/issues/40)) ([b9cbfd7](https://github.com/osanderson/singpass-client-go/commit/b9cbfd73ab3ccabc73e8033db713f19d2c0888c3))
* **web:** keep personal data out of the login session ([#46](https://github.com/osanderson/singpass-client-go/issues/46)) ([e7ed2bf](https://github.com/osanderson/singpass-client-go/commit/e7ed2bfc6beb8bf6ee1151f5549e0b66f5bb014d))


### Bug Fixes

* reject redirect URIs that use an IP address ([#45](https://github.com/osanderson/singpass-client-go/issues/45)) ([ff9a1cd](https://github.com/osanderson/singpass-client-go/commit/ff9a1cdd13b16333644c3147d4091e6d805704af))
* say Singpass and Corppass both reject a redirecting JWKS URL ([#43](https://github.com/osanderson/singpass-client-go/issues/43)) ([765c97b](https://github.com/osanderson/singpass-client-go/commit/765c97b58f152e0830bb4dd34393c1fd7966c250))


### Documentation

* add onboarding and troubleshooting guides ([#44](https://github.com/osanderson/singpass-client-go/issues/44)) ([2158fc8](https://github.com/osanderson/singpass-client-go/commit/2158fc80393618dfe23e8bab9a8841e1ea00e016))

## [0.7.0](https://github.com/osanderson/singpass-client-go/compare/v0.6.2...v0.7.0) (2026-09-27)


### Features

* **myinfo:** add typed person and entity profiles ([#38](https://github.com/osanderson/singpass-client-go/issues/38)) ([5102816](https://github.com/osanderson/singpass-client-go/commit/5102816c11b3546fa2795684a18a0f59042ce08d))

## [0.6.2](https://github.com/osanderson/singpass-client-go/compare/v0.6.1...v0.6.2) (2026-09-27)


### Bug Fixes

* **deps:** update FAPIgo to v0.36.0 ([#36](https://github.com/osanderson/singpass-client-go/issues/36)) ([307cf3a](https://github.com/osanderson/singpass-client-go/commit/307cf3ae8a9fc0d4854b4c2d2a26568312960fee))

## [0.6.1](https://github.com/osanderson/singpass-client-go/compare/v0.6.0...v0.6.1) (2026-09-27)


### Documentation

* bring docs up to date with v0.6.0 and correct stale claims ([#33](https://github.com/osanderson/singpass-client-go/issues/33)) ([d34aa9e](https://github.com/osanderson/singpass-client-go/commit/d34aa9e095d1f4cec4fe700d73917785ad2ff0ff))

## [0.6.0](https://github.com/osanderson/singpass-client-go/compare/v0.5.2...v0.6.0) (2026-09-27)


### ⚠ BREAKING CHANGES

* Identity.SubjectAttributes() returns SubjectAttributes instead of map[string]any (use .Raw for the map, .Present() instead of a nil check), and ActingParty.Attributes is a SubjectAttributes (use .Raw for the map).

### Features

* add singpass-keygen command and keyfile write helpers ([#30](https://github.com/osanderson/singpass-client-go/issues/30)) ([0485e7a](https://github.com/osanderson/singpass-client-go/commit/0485e7a0270c6ac7960816da8601127796965c32))
* **myinfo:** add Leaves, EffectiveSource, Label and typed Corppass records ([#29](https://github.com/osanderson/singpass-client-go/issues/29)) ([56ecbd4](https://github.com/osanderson/singpass-client-go/commit/56ecbd4dcb343851df06e7914b09b9609322683d))
* typed SubjectAttributes for sub_attributes and act.sub_attributes ([c071a51](https://github.com/osanderson/singpass-client-go/commit/c071a51d35b18d939f4aa36e4e38f7caf065a2ac))
* **web:** add SecureHeaders and NoStore; __Host- cookie names by default ([#26](https://github.com/osanderson/singpass-client-go/issues/26)) ([c2ec830](https://github.com/osanderson/singpass-client-go/commit/c2ec830adc31676214de9bb67dd7cd39116655aa))


### Bug Fixes

* **deps:** bump FAPIgo to v0.35.0 ([#32](https://github.com/osanderson/singpass-client-go/issues/32)) ([b34b1aa](https://github.com/osanderson/singpass-client-go/commit/b34b1aa9fde113de804d32e0612eac9dfc6363af))

## [0.5.2](https://github.com/osanderson/singpass-client-go/compare/v0.5.1...v0.5.2) (2026-09-27)


### Bug Fixes

* **deps:** bump FAPIgo to v0.34.0 ([#24](https://github.com/osanderson/singpass-client-go/issues/24)) ([ed50510](https://github.com/osanderson/singpass-client-go/commit/ed50510b5a17726091e0f5029acd06706c3093e0))

## [0.5.1](https://github.com/osanderson/singpass-client-go/compare/v0.5.0...v0.5.1) (2026-09-26)


### Documentation

* point to the published Myinfo and Myinfo Business test personas ([#22](https://github.com/osanderson/singpass-client-go/issues/22)) ([42653d3](https://github.com/osanderson/singpass-client-go/commit/42653d3104f3221e1b45a62ebe932431a25dbd59))

## [0.5.0](https://github.com/osanderson/singpass-client-go/compare/v0.4.0...v0.5.0) (2026-09-26)


### ⚠ BREAKING CHANGES

* NewMyinfoBusiness no longer accepts a /userinfo sub equal to the client_id. If a Corppass environment still sends it (the error is "UserInfo response sub does not match the ID token's sub"), set MyinfoBusinessOptions.TolerateUserInfoSubjectClientID.

### Features

* check the Corppass /userinfo sub strictly now Corppass has fixed it ([aaeaaec](https://github.com/osanderson/singpass-client-go/commit/aaeaaec36f98e3588ffb37ca0fb71a32641dddb0))

## [0.4.0](https://github.com/osanderson/singpass-client-go/compare/v0.3.0...v0.4.0) (2026-09-26)


### Features

* upgrade FAPIgo to v0.33.0; singpasstest issues Singpass/Corppass id_token claims ([#18](https://github.com/osanderson/singpass-client-go/issues/18)) ([87aaacc](https://github.com/osanderson/singpass-client-go/commit/87aaacc6cd23f96c51f78b4f28ad803ed9d3ba41))

## [0.3.0](https://github.com/osanderson/singpass-client-go/compare/v0.2.0...v0.3.0) (2026-09-26)


### Features

* add Environment option with production issuers and a go-live checklist ([#16](https://github.com/osanderson/singpass-client-go/issues/16)) ([95b35bc](https://github.com/osanderson/singpass-client-go/commit/95b35bca9a33e74c58497190f0ffa3320e1415b3))
* add singpasstest fake server and demo mock mode ([#10](https://github.com/osanderson/singpass-client-go/issues/10)) ([83f5134](https://github.com/osanderson/singpass-client-go/commit/83f5134cf0b308bc02dcc6bc94eb86e7b82ab2b9))
* add sqlstore, a durable SQL session store for production ([#17](https://github.com/osanderson/singpass-client-go/issues/17)) ([6a0820d](https://github.com/osanderson/singpass-client-go/commit/6a0820d33f6d335df727c35bc66446cdf6d70b1b))

## [0.2.0](https://github.com/osanderson/singpass-client-go/compare/v0.1.1...v0.2.0) (2026-09-25)


### ⚠ BREAKING CHANGES

* tidy the public API before 1.0 ([#8](https://github.com/osanderson/singpass-client-go/issues/8))

### Features

* tidy the public API before 1.0 ([#8](https://github.com/osanderson/singpass-client-go/issues/8)) ([6436b3b](https://github.com/osanderson/singpass-client-go/commit/6436b3be764f80e854a7248823e0a8ca5523b164))

## [0.1.1](https://github.com/osanderson/singpass-client-go/compare/v0.1.0...v0.1.1) (2026-09-25)


### Documentation

* restructure README and add examples, security policy and templates ([#6](https://github.com/osanderson/singpass-client-go/issues/6)) ([47540cf](https://github.com/osanderson/singpass-client-go/commit/47540cf9041ac689bc1ce25a644b118732a8b212))

## 0.1.0 (2026-09-25)


### Documentation

* add Singpass and Corppass integration quirks ([#1](https://github.com/osanderson/singpass-client-go/issues/1)) ([38d9fb2](https://github.com/osanderson/singpass-client-go/commit/38d9fb2e7c778e3174f751e80929f8fb1c631879))
