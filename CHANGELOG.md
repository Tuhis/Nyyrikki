# Changelog

## [0.7.0](https://github.com/Tuhis/Nyyrikki/compare/v0.6.0...v0.7.0) (2026-11-16)


### Features

* **gateway:** tell agents to use their own access before Nyyrikki ([#76](https://github.com/Tuhis/Nyyrikki/issues/76)) ([bdaf294](https://github.com/Tuhis/Nyyrikki/commit/bdaf294a20460e206534c49c992e827061e60343))

## [0.6.0](https://github.com/Tuhis/Nyyrikki/compare/v0.5.0...v0.6.0) (2026-11-14)


### Features

* **deploy:** licence notices in the image and the CLI release (docs/09 PB2) ([#52](https://github.com/Tuhis/Nyyrikki/issues/52)) ([e799d69](https://github.com/Tuhis/Nyyrikki/commit/e799d69b32efc610b73ee0ef47280fa5db2eb436))
* **deploy:** local quickstart on kind with a real Telegram bot (docs/09 PB5) ([#56](https://github.com/Tuhis/Nyyrikki/issues/56)) ([7f8e64f](https://github.com/Tuhis/Nyyrikki/commit/7f8e64f4ed46a97713212d05f30d71fef9f4d302))
* SOPS files encrypted with Google Cloud KMS as a third target type (R14, docs/10 SO1–SO5) ([#75](https://github.com/Tuhis/Nyyrikki/issues/75)) ([940a833](https://github.com/Tuhis/Nyyrikki/commit/940a833ed0bb18a194cfa9caae9328d3433dc255))


### Bug Fixes

* **ci:** build go tool covdata before the coverage gate's test run ([#57](https://github.com/Tuhis/Nyyrikki/issues/57)) ([5458bde](https://github.com/Tuhis/Nyyrikki/commit/5458bde4d96e6d92fa2c138fab7c6fe9234f078a))
* **test:** servertest starts again on another port when its free port was taken ([#62](https://github.com/Tuhis/Nyyrikki/issues/62)) ([fc2a68a](https://github.com/Tuhis/Nyyrikki/commit/fc2a68a59bb72cbd7403cb858f28a426c9f76cb9))

## [0.5.0](https://github.com/Tuhis/Nyyrikki/compare/v0.4.0...v0.5.0) (2026-11-01)


### Features

* **deploy:** accept OpenSSH 8.9 and Ubuntu 22.04 hosts (docs/07 OD7) ([#55](https://github.com/Tuhis/Nyyrikki/issues/55)) ([e514341](https://github.com/Tuhis/Nyyrikki/commit/e514341b63ec7305d2cb8e2b8684c1827fabd8ac))
* **deploy:** sign releases key-less with cosign, with SBOM and provenance (docs/09 PB3) ([#54](https://github.com/Tuhis/Nyyrikki/issues/54)) ([0958e05](https://github.com/Tuhis/Nyyrikki/commit/0958e05350eb58a8e2b1a52df4123c9a4db10995))

## [0.4.0](https://github.com/Tuhis/Nyyrikki/compare/v0.3.0...v0.4.0) (2026-11-01)


### Features

* **cli:** offline sessions for nyyrikki login (OD18) ([#41](https://github.com/Tuhis/Nyyrikki/issues/41)) ([0abec49](https://github.com/Tuhis/Nyyrikki/commit/0abec492a50ade63213034ca69876e6b36565ebd))
* **credentials:** signed SSH trust bundle at /hosts/&lt;target&gt;/trust (docs/08 SE3) ([#45](https://github.com/Tuhis/Nyyrikki/issues/45)) ([3a1e53c](https://github.com/Tuhis/Nyyrikki/commit/3a1e53c4bc0d343e25dd565a34c9cea9f0d66f98))
* **credentials:** SSH CA keys from one Secret, made by a hook, rotated in place (docs/08 SE1) ([#42](https://github.com/Tuhis/Nyyrikki/issues/42)) ([6853787](https://github.com/Tuhis/Nyyrikki/commit/68537871a4f1b853e0b4006629061c1cebff883a))
* **deploy:** SSH host enrollment and trust pull in the setup script, setup docs (docs/08 SE6) ([#50](https://github.com/Tuhis/Nyyrikki/issues/50)) ([8f08181](https://github.com/Tuhis/Nyyrikki/commit/8f08181895a438c364aed378236cdc1b7bb26963))
* **elevation:** SSH defaults, target groups, global host CAs and nyyrikki ssh (docs/08 SE2) ([#43](https://github.com/Tuhis/Nyyrikki/issues/43)) ([e39159d](https://github.com/Tuhis/Nyyrikki/commit/e39159d84136c6aed51a2039ba0d040d6c7990ab))
* **gateway:** SSH host enrollment with one Telegram tap (docs/08 SE5) ([#47](https://github.com/Tuhis/Nyyrikki/issues/47)) ([1bf594d](https://github.com/Tuhis/Nyyrikki/commit/1bf594d00163baccf56105ed440a4d912acda9b7))
* **gateway:** trust Nyyrikki's host CA and check SSH hosts before approval (docs/08 SE4) ([#46](https://github.com/Tuhis/Nyyrikki/issues/46)) ([8d61ee3](https://github.com/Tuhis/Nyyrikki/commit/8d61ee38006f7f72a70da5b07a22f719bc136719))

## [0.3.0](https://github.com/Tuhis/Nyyrikki/compare/v0.2.1...v0.3.0) (2026-10-30)


### Features

* **cli:** ask for offline_access in login --mcp where it is offered ([#29](https://github.com/Tuhis/Nyyrikki/issues/29)) ([2012369](https://github.com/Tuhis/Nyyrikki/commit/20123695e983be6a76adb03513600f2f3d2973be))
* SSH hosts as a second target type (R10, docs/07 SH1–SH6) ([#30](https://github.com/Tuhis/Nyyrikki/issues/30)) ([2a2df53](https://github.com/Tuhis/Nyyrikki/commit/2a2df536abfe0826d64f20d9c196947af98a5663))

## [0.2.1](https://github.com/Tuhis/Nyyrikki/compare/v0.2.0...v0.2.1) (2026-10-29)


### Bug Fixes

* **cli:** send PKCE in the device grant, and measure DCR for MCP harnesses (docs/01 M9) ([#26](https://github.com/Tuhis/Nyyrikki/issues/26)) ([a442cdb](https://github.com/Tuhis/Nyyrikki/commit/a442cdb675a7433a233894f99b6a476dddca7033))

## [0.2.0](https://github.com/Tuhis/Nyyrikki/compare/v0.1.0...v0.2.0) (2026-10-28)


### Features

* **deploy:** publish the chart to oci://ghcr.io/tuhis/charts ([#22](https://github.com/Tuhis/Nyyrikki/issues/22)) ([bf3c382](https://github.com/Tuhis/Nyyrikki/commit/bf3c3820a5acc0470ea5452e258f913da34ae3cc))

## 0.1.0 (2026-10-27)


### Features

* **deploy:** image, Helm chart, setup docs and release workflow (M4) ([#11](https://github.com/Tuhis/Nyyrikki/issues/11)) ([08650c7](https://github.com/Tuhis/Nyyrikki/commit/08650c7f2119da0b3864f0af273a04532f31b1eb))
* **deploy:** trust extra CA certificates from a ConfigMap ([#16](https://github.com/Tuhis/Nyyrikki/issues/16)) ([8537368](https://github.com/Tuhis/Nyyrikki/commit/8537368aa414495740a1297ff3b5353ee424cf8c))
* gateway core, audit log, kubectl pass-through and Telegram escalation (M1–M3) ([#10](https://github.com/Tuhis/Nyyrikki/issues/10)) ([286deeb](https://github.com/Tuhis/Nyyrikki/commit/286deeb12452b1b9cff2c2a4c42993a9c24307ab))


### Bug Fixes

* **deploy:** make the Keycloak setup work with Keycloak 26.8 ([#15](https://github.com/Tuhis/Nyyrikki/issues/15)) ([55865cd](https://github.com/Tuhis/Nyyrikki/commit/55865cd062292b7c3029be9a6726fe5226e42e55))
* report an interactive run cut at elevation expiry as expired ([#18](https://github.com/Tuhis/Nyyrikki/issues/18)) ([f975592](https://github.com/Tuhis/Nyyrikki/commit/f975592f3b7e86cd16650985bd758bc8e42f0276))
