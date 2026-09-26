# Changelog

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
