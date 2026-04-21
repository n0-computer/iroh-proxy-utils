# Changelog

## [0.2.0](https://github.com/n0-computer/iroh-proxy-utils/compare/v0.1.0..0.2.0) - 2026-04-21

### Deps

- Update to iroh 0.98 ([#19](https://github.com/n0-computer/iroh-proxy-utils/issues/19)) - ([f146272](https://github.com/n0-computer/iroh-proxy-utils/commit/f1462723885f571e8f5e4daddc58320fbdd66cc8))

## [0.1.0] - 2026-04-09

### ⛰️  Features

- *(HTTP CONNECT)* Support HTTP request proxying - ([6bc414e](https://github.com/n0-computer/iroh-proxy-utils/commit/6bc414e56a8f4d9b1f6c01ac12bd07136bac8e1e))
- *(Request)* Expose Request::parse - ([ad9e463](https://github.com/n0-computer/iroh-proxy-utils/commit/ad9e4639cfd87ac8a1997811d22bfc12d0a78a0f))
- *(auth)* Add auth interface for HTTP CONNECT - ([b200aaa](https://github.com/n0-computer/iroh-proxy-utils/commit/b200aaa23c6c6c84878e70ad2c962deae60aabf4))
- Sup - ([0057711](https://github.com/n0-computer/iroh-proxy-utils/commit/005771177b147b93e2f90b6d9240494c493b059f))
- Stream-oriented client proxy - ([a922c27](https://github.com/n0-computer/iroh-proxy-utils/commit/a922c27a0510b365f012e12e314b8b778334d097))
- Use hyper for downstream ingest, support HTTP/2 ([#8](https://github.com/n0-computer/iroh-proxy-utils/issues/8)) - ([b200b55](https://github.com/n0-computer/iroh-proxy-utils/commit/b200b55d6c9b03b20bb1a77fc2ce84a5ef4a8a36))
- Support websocket upgrades ([#9](https://github.com/n0-computer/iroh-proxy-utils/issues/9)) - ([0fa19ea](https://github.com/n0-computer/iroh-proxy-utils/commit/0fa19ea75828ee2899cd01778980e43338a4f08e))
- Add support for UDS listeners on downstream ([#10](https://github.com/n0-computer/iroh-proxy-utils/issues/10)) - ([9468236](https://github.com/n0-computer/iroh-proxy-utils/commit/9468236657df273592f40218a1788edc277964b4))
- Metrics for upstream proxy ([#14](https://github.com/n0-computer/iroh-proxy-utils/issues/14)) - ([282c71a](https://github.com/n0-computer/iroh-proxy-utils/commit/282c71aa74175efa8bc0e535bfba22873e9baba3))
- Downstream metrics and avoid dropping conns prematurely#15 ([#16](https://github.com/n0-computer/iroh-proxy-utils/issues/16)) - ([38ef14f](https://github.com/n0-computer/iroh-proxy-utils/commit/38ef14f7bc215348d47987563bb1b5198cc91f40))

### 🐛 Bug Fixes

- *(TunnelListener)* Accept the right auth signature - ([2446dd8](https://github.com/n0-computer/iroh-proxy-utils/commit/2446dd8708ad6e81e2896b143152f5c690baa217))
- Don't double-close the sendstream in upstream ([#13](https://github.com/n0-computer/iroh-proxy-utils/issues/13)) - ([a7a4d7a](https://github.com/n0-computer/iroh-proxy-utils/commit/a7a4d7ad9a508f548982be7bf2f0a9f945f0aff2))
- Use origin-form URI when forwarding upgrade requests to origin ([#12](https://github.com/n0-computer/iroh-proxy-utils/issues/12)) - ([dc0dcc6](https://github.com/n0-computer/iroh-proxy-utils/commit/dc0dcc67154fce4ba6b3e67a642c4de18d26cea3))

### 🚜 Refactor

- Make request fields public - ([e88ec59](https://github.com/n0-computer/iroh-proxy-utils/commit/e88ec593d1a74aa94c07ac079c0872a829d595bc))
- HttpConnectListnerHandle -> TunnelListener - ([aeb4a19](https://github.com/n0-computer/iroh-proxy-utils/commit/aeb4a191630d5c33aeff530818241ca2d22622c1))
- Improve protocol and API ([#2](https://github.com/n0-computer/iroh-proxy-utils/issues/2)) - ([f0a5605](https://github.com/n0-computer/iroh-proxy-utils/commit/f0a5605d0c941525839de6f20dcfa1666993f8d0))
- Properly support different forward modes ([#3](https://github.com/n0-computer/iroh-proxy-utils/issues/3)) - ([dd8032f](https://github.com/n0-computer/iroh-proxy-utils/commit/dd8032f7eec2ef5618609b6be8aae323bf499157))
- Improve API and add tests ([#4](https://github.com/n0-computer/iroh-proxy-utils/issues/4)) - ([36bc77a](https://github.com/n0-computer/iroh-proxy-utils/commit/36bc77a116bb34daa7709964faf1f0a3f17d229e))
- Update ALPN, README and deps ([#6](https://github.com/n0-computer/iroh-proxy-utils/issues/6)) - ([e970a8c](https://github.com/n0-computer/iroh-proxy-utils/commit/e970a8c581aa9ef9b0bc3bdaa45ea36ea582b537))

### ⚙️ Miscellaneous Tasks

- Cleanup before 0.1.0 release ([#18](https://github.com/n0-computer/iroh-proxy-utils/issues/18)) - ([710ceb5](https://github.com/n0-computer/iroh-proxy-utils/commit/710ceb58a562fa39c5d37938168559699f5f838e))

### Deps

- Update to iroh 0.97 ([#17](https://github.com/n0-computer/iroh-proxy-utils/issues/17)) - ([a8427ac](https://github.com/n0-computer/iroh-proxy-utils/commit/a8427ac7b3e66f7bf680cd3c9a3ccbb53344efd8))


