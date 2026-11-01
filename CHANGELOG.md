# Changelog

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
