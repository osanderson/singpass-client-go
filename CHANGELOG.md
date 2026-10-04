# Changelog

## [0.14.2](https://github.com/osanderson/singpass-client-go/compare/v0.14.1...v0.14.2) (2026-10-04)


### Bug Fixes

* **deps:** bump modernc.org/sqlite from 1.59.0 to 1.60.1 ([#102](https://github.com/osanderson/singpass-client-go/issues/102)) ([c912242](https://github.com/osanderson/singpass-client-go/commit/c912242d3f6444002036a77dd94d136da7e6976f))

## [0.14.1](https://github.com/osanderson/singpass-client-go/compare/v0.14.0...v0.14.1) (2026-10-04)


### Bug Fixes

* **deps:** bump FAPIgo to v0.48.1 ([#108](https://github.com/osanderson/singpass-client-go/issues/108)) ([2fa10fe](https://github.com/osanderson/singpass-client-go/commit/2fa10fe8c9f397666c35e2d73000f55026335aba))

## [0.14.0](https://github.com/osanderson/singpass-client-go/compare/v0.13.0...v0.14.0) (2026-10-02)


### ⚠ BREAKING CHANGES

* **deps:** protocol sessions now keep FAPIgo's opaque session record. sqlstore moves them to a new table, <prefix>auth_sessions_v2: run CreateTables, or add the table to your own migrations, before deploying, then drop <prefix>auth_sessions. A custom Dependencies.Sessions store must persist NewSession.Record as is and return it as ConsumedSession.Record. Logins in progress during the deploy fail at their callback. See UPGRADING.md.

### Features

* **singpasstest:** refuse a repeated Authorization header at /userinfo ([58fed4d](https://github.com/osanderson/singpass-client-go/commit/58fed4d4bd6ad2c9c561c66c36eccad9e946b6ed))
* **singpasstest:** refuse a repeated client_id or request_uri at the authorization endpoint ([#105](https://github.com/osanderson/singpass-client-go/issues/105)) ([75d5cc2](https://github.com/osanderson/singpass-client-go/commit/75d5cc27e756e96ac8fc2f71f292ef0cec980c12))


### Bug Fixes

* **deps:** bump FAPIgo to v0.43.0 ([#107](https://github.com/osanderson/singpass-client-go/issues/107)) ([195ca23](https://github.com/osanderson/singpass-client-go/commit/195ca232c49a4c8fc9ebca71edaea45afcd47180))
* **deps:** pin FAPIgo to main ahead of v0.43.0 ([6355777](https://github.com/osanderson/singpass-client-go/commit/635577755a59e888c8c706233c5b439387e2c611))
* **deps:** pin FAPIgo to main ebc4b5f ([58fed4d](https://github.com/osanderson/singpass-client-go/commit/58fed4d4bd6ad2c9c561c66c36eccad9e946b6ed))
* **singpasstest:** refuse a pushed authorization request without the openid scope, as Singpass does ([58fed4d](https://github.com/osanderson/singpass-client-go/commit/58fed4d4bd6ad2c9c561c66c36eccad9e946b6ed))


### Documentation

* give the MySQL SQL for sqlstore's v0.14.0 table, and the error when it's missing ([#104](https://github.com/osanderson/singpass-client-go/issues/104)) ([c131a4e](https://github.com/osanderson/singpass-client-go/commit/c131a4efa23eb6d70715dcca475ad957f85f6641))

## [0.13.0](https://github.com/osanderson/singpass-client-go/compare/v0.12.0...v0.13.0) (2026-10-01)


### ⚠ BREAKING CHANGES

* under AssuranceProduction, New and the product constructors refuse a DPoP key generated per process, because Singpass binds each login to the DPoP key it started with. Set DPoPKey to a key every instance loads, or build Dependencies.Keys with NewKeyManagerWithDPoP.

### Features

* add Dependencies.AllowedPrivateHosts, for a fake issuer reached by a Docker Compose service name ([29f4049](https://github.com/osanderson/singpass-client-go/commit/29f4049159926060b88fcae7e06b41cf4c4c6d5e))
* share one DPoP key across instances (DPoPKey, NewKeyManagerWithDPoP), and require it in production ([7fd4b5f](https://github.com/osanderson/singpass-client-go/commit/7fd4b5fb2e3e87fa535552cf96e9a514312a68b3))
* **singpass-fake-server:** publish a container image ([#91](https://github.com/osanderson/singpass-client-go/issues/91)) ([afa1556](https://github.com/osanderson/singpass-client-go/commit/afa1556ca2e0818d4c1c398a92ded666f4f49d61))
* **singpass-fake-server:** run with no configuration ([#90](https://github.com/osanderson/singpass-client-go/issues/90)) ([186d6f2](https://github.com/osanderson/singpass-client-go/commit/186d6f23393c6d520d1d205caadead7adcf16e14))
* **singpass-fake-server:** serve HTTPS, for apps that reach it by a service name ([29f4049](https://github.com/osanderson/singpass-client-go/commit/29f4049159926060b88fcae7e06b41cf4c4c6d5e))
* **singpasstest:** add a dashboard at /_fake/ ([#94](https://github.com/osanderson/singpass-client-go/issues/94)) ([a8e98ae](https://github.com/osanderson/singpass-client-go/commit/a8e98ae7043f69515ff6b38ff3635f12ef9db701))
* **singpasstest:** choose the test user per login with X-Custom-* headers ([#89](https://github.com/osanderson/singpass-client-go/issues/89)) ([f07c49e](https://github.com/osanderson/singpass-client-go/commit/f07c49e7a280467e0d18975804c70660473d10e5))
* **singpasstest:** explain rejections, and how to fix them ([#93](https://github.com/osanderson/singpass-client-go/issues/93)) ([391e4ac](https://github.com/osanderson/singpass-client-go/commit/391e4acfae20652b26be2ef60b8cccb8dbc4fed8))


### Bug Fixes

* **deps:** bump FAPIgo to v0.41.0 ([8d2438a](https://github.com/osanderson/singpass-client-go/commit/8d2438a8c016c2cfee05b5392d22a2adc8a36643))
* **singpasstest:** answer /userinfo without credentials with a bare challenge, as RFC 6750 asks ([8d2438a](https://github.com/osanderson/singpass-client-go/commit/8d2438a8c016c2cfee05b5392d22a2adc8a36643))
* **singpasstest:** bind each code to the DPoP key used at PAR, as Singpass does ([7fd4b5f](https://github.com/osanderson/singpass-client-go/commit/7fd4b5fb2e3e87fa535552cf96e9a514312a68b3))


### Documentation

* document the shared DPoP key and the invalid_dpop_proof it prevents ([7fd4b5f](https://github.com/osanderson/singpass-client-go/commit/7fd4b5fb2e3e87fa535552cf96e9a514312a68b3))

## [0.12.0](https://github.com/osanderson/singpass-client-go/compare/v0.11.0...v0.12.0) (2026-09-30)


### Features

* **web:** add LoginRateLimit to limit how fast one client starts logins ([d368a1d](https://github.com/osanderson/singpass-client-go/commit/d368a1db6657ffe4267800c34bd261c09b6fdae9))


### Bug Fixes

* **deps:** bump FAPIgo to v0.40.0 ([#84](https://github.com/osanderson/singpass-client-go/issues/84)) ([79b39c3](https://github.com/osanderson/singpass-client-go/commit/79b39c3be55c505f09749346c1f5d21e54e7fefa))
* **myinfo:** keep item values that look like JSON as strings ([d368a1d](https://github.com/osanderson/singpass-client-go/commit/d368a1db6657ffe4267800c34bd261c09b6fdae9))
* refuse Dependencies.Debug under AssuranceProduction, and warn on a production issuer without it ([d368a1d](https://github.com/osanderson/singpass-client-go/commit/d368a1db6657ffe4267800c34bd261c09b6fdae9))
* **sqlstore:** store login sessions under a SHA-256 hash of the session id; users are signed out once on upgrade ([d368a1d](https://github.com/osanderson/singpass-client-go/commit/d368a1db6657ffe4267800c34bd261c09b6fdae9))


### Documentation

* note the stricter loopback rule in the v0.12.0 upgrade guide ([#85](https://github.com/osanderson/singpass-client-go/issues/85)) ([182a65e](https://github.com/osanderson/singpass-client-go/commit/182a65e7681447e777175c1dfaaf276322fbb49c))
* production checklist for rate limiting and login-session data ([d368a1d](https://github.com/osanderson/singpass-client-go/commit/d368a1db6657ffe4267800c34bd261c09b6fdae9))

## [0.11.0](https://github.com/osanderson/singpass-client-go/compare/v0.10.0...v0.11.0) (2026-09-29)


### Features

* **myinfo:** accept entity.identity and fix the grants last_updated_date scope ([#76](https://github.com/osanderson/singpass-client-go/issues/76)) ([ce832f4](https://github.com/osanderson/singpass-client-go/commit/ce832f4fa33cf8adc64c88aa7d83f6d907b4105d))

## [0.10.0](https://github.com/osanderson/singpass-client-go/compare/v0.9.2...v0.10.0) (2026-09-29)


### Features

* add singpass-fake-server, the fake servers as a standalone command ([#67](https://github.com/osanderson/singpass-client-go/issues/67)) ([94ccd69](https://github.com/osanderson/singpass-client-go/commit/94ccd694cdbed2a685ad26c9ba868e9bb69352fb))
* **demo:** show masked NRIC, employer, CPF contribution and Corppass email ([#65](https://github.com/osanderson/singpass-client-go/issues/65)) ([cbf1cf6](https://github.com/osanderson/singpass-client-go/commit/cbf1cf6482cbb13c549094b01e6ebd90d21f5418))
* **keyfile:** load SEC1 EC keys, as openssl writes them ([#75](https://github.com/osanderson/singpass-client-go/issues/75)) ([a0f16c2](https://github.com/osanderson/singpass-client-go/commit/a0f16c2d504ed2981d7b54c4cc07bc4316f729b4))
* **keygen:** publish several keys with -sig and -enc lists ([#62](https://github.com/osanderson/singpass-client-go/issues/62)) ([2430a83](https://github.com/osanderson/singpass-client-go/commit/2430a8398768a4dc3060a2af57f6efee90725ee1))
* **myinfo:** add Myinfo Business scope constants ([#60](https://github.com/osanderson/singpass-client-go/issues/60)) ([9a6b10d](https://github.com/osanderson/singpass-client-go/commit/9a6b10de494cec808a78f22cda64642b1d289971))
* **myinfo:** add scope helpers and typed NOA, vehicle, HDB and licence data ([#59](https://github.com/osanderson/singpass-client-go/issues/59)) ([f192ea5](https://github.com/osanderson/singpass-client-go/commit/f192ea5666795f45de36be2509d446ed229fcc21))
* **myinfo:** complete EntityProfile from Corppass's entity_info specification ([#61](https://github.com/osanderson/singpass-client-go/issues/61)) ([b15388e](https://github.com/osanderson/singpass-client-go/commit/b15388edb6665b932658e3d0ebf90b522a479941))
* **myinfo:** type every Myinfo item and the Corppass account block ([#64](https://github.com/osanderson/singpass-client-go/issues/64)) ([7b62c93](https://github.com/osanderson/singpass-client-go/commit/7b62c93b40bb9ef9f48820526056d900227d027e))
* **singpasstest:** load test users from JSON files ([#70](https://github.com/osanderson/singpass-client-go/issues/70)) ([b83d82f](https://github.com/osanderson/singpass-client-go/commit/b83d82f384ee15e3b620fee348791ae6ff7e6891))
* **singpasstest:** log in as any user, and richer built-in test users ([#66](https://github.com/osanderson/singpass-client-go/issues/66)) ([24e93fa](https://github.com/osanderson/singpass-client-go/commit/24e93fa29c6b27de62092fb11e7e14d6dc975090))
* support the Singpass Login context message and mobile-app redirects ([#58](https://github.com/osanderson/singpass-client-go/issues/58)) ([d3a7338](https://github.com/osanderson/singpass-client-go/commit/d3a7338410fc73d40a682b09fb793466853cd88b))


### Documentation

* add an upgrade guide and a stability policy ([#56](https://github.com/osanderson/singpass-client-go/issues/56)) ([0f32ca8](https://github.com/osanderson/singpass-client-go/commit/0f32ca8b57433987dde7bb4fad85359f9999b953))
* cover the standalone fake server and the typed profiles ([#68](https://github.com/osanderson/singpass-client-go/issues/68)) ([2276115](https://github.com/osanderson/singpass-client-go/commit/2276115d0e741bc1e8c4a2573f0ecc0b88816151))
* state in the package docs that the library is unofficial ([#71](https://github.com/osanderson/singpass-client-go/issues/71)) ([7349535](https://github.com/osanderson/singpass-client-go/commit/7349535f6b8b878f8bc355bba533b579d66a108a))

## [0.9.2](https://github.com/osanderson/singpass-client-go/compare/v0.9.1...v0.9.2) (2026-09-28)


### Bug Fixes

* **deps:** update FAPIgo to v0.39.0 ([#54](https://github.com/osanderson/singpass-client-go/issues/54)) ([8a9363e](https://github.com/osanderson/singpass-client-go/commit/8a9363e620f18f686a7b0e48c50b1ac0b27ca860))

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
