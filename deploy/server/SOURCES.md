# Corresponding source of the qualor/server image

Generated from `deploy/server/debian-sources.json` by `pnpm deploy:sources --index`; do not edit.

The complete corresponding source of the copyleft components of `qualor/server`.
Each release publishes these files, byte for byte, in the
companion image `qualor/server-sources:<same tag>` (under `/sources/`) and on its release
page. `sha256sum -c SHA256SUMS` checks them: every file must have exactly this SHA-256.

## Debian source packages of `qualor/server`

Every Debian binary package installed in `qualor/server` (base `gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f`), by source package at the installed version, in `debian/`. Each `.dsc` was checked against the SHA-256 of the Debian Sources index, and every other file against its `.dsc`.

| Source | Version | Binary packages | Files (SHA-256) |
| --- | --- | --- | --- |
| base-files | 12.4+deb12u15 | base-files | `base-files_12.4+deb12u15.dsc` `e531274d0c3916dacfe55bbd27148d775b004e1836bc2fbb01549f142d524e8c`<br>`base-files_12.4+deb12u15.tar.xz` `9fb369194365fe9da74621da247ea70884fc3d1d9c063db310764ef0e43c02c5` |
| ca-certificates | 20250419~deb12u1 | ca-certificates | `ca-certificates_20250419~deb12u1.dsc` `72339e810ef8237a4c346540b52baf49607172cc849c2680328a608ce0f6a34b`<br>`ca-certificates_20250419~deb12u1.tar.xz` `b2a431cbab9a0ece921cffacbe238dc27a3e382ad4a1806dc8968c5eff30471d` |
| gcc-12 | 12.2.0-14+deb12u1 | gcc-12-base, libgcc-s1, libgomp1, libstdc++6 | `gcc-12_12.2.0-14+deb12u1.dsc` `3aed0b189189c744dc9f4b74798a51d3e512ea85e492568db788a927c88e20ba`<br>`gcc-12_12.2.0.orig.tar.gz` `b8298be16aeeb96a889c6afed0a8e2241b47452e89cc81fe65ea849d5c740fcb`<br>`gcc-12_12.2.0-14+deb12u1.debian.tar.xz` `59f7f7763a0c355e3f27ff9e7ac80d06382b29939361a87e7b139226bfe7402e` |
| glibc | 2.36-9+deb12u14 | libc6 | `glibc_2.36-9+deb12u14.dsc` `cfe1f0b8dc1fa211ce5a45b3725cc38b29f88667f1140ebdca6de35cf9c6f1fd`<br>`glibc_2.36.orig.tar.xz` `a543c02070d46ccaf866957efd13f10c924daa74c86a90a0254db09a92a708ee`<br>`glibc_2.36-9+deb12u14.debian.tar.xz` `cf4ac9cd98185452cae3ef34e2e4ee12753e3d93fd0c62c61396d4a47eec902f` |
| media-types | 10.0.0 | media-types | `media-types_10.0.0.dsc` `d2e34e90508ac2c21c3cc6c01e2cf186093a8d2edcdc279e7d280a0a4ffe132d`<br>`media-types_10.0.0.tar.xz` `fe0f5adcb153e642c5e3295b811cddf6ba12bf3df5e7c6c012f3b98dfae1d245` |
| netbase | 6.4 | netbase | `netbase_6.4.dsc` `dc26cfcaa49fd874cc27c65216b2f8b6d3ad62845b78da4bdf0aea55592af756`<br>`netbase_6.4.tar.xz` `fa6621826ff1150e581bd90bc3c8a4ecafe5df90404f207db6dcdf2c75f26ad7` |
| openssl | 3.0.20-1~deb12u2 | libssl3 | `openssl_3.0.20-1~deb12u2.dsc` `a614474a2773c23b10c0d65f4eccbcf93fdac4749afb7c26d76e1b0340154d3d`<br>`openssl_3.0.20.orig.tar.gz` `c80a01dfc70ece4dc21168932c37739042d404d46ccc81a5986dd75314ecda6f`<br>`openssl_3.0.20.orig.tar.gz.asc` `07669568ab34cf3a4dcf8fd8e0d85cacdacfaa10d5ab51bdc6fc47c22fa6b33a`<br>`openssl_3.0.20-1~deb12u2.debian.tar.xz` `7279efe85c359500c95aa88347e3395dd303d7566e2bb818d80d96e0c3bb9629` |
| tzdata | 2026b-0+deb12u1 | tzdata | `tzdata_2026b-0+deb12u1.dsc` `1a6e7b80823607130b79a12e5dff0d03ed81feb14faf5fffad94841e54cfe988`<br>`tzdata_2026b.orig.tar.gz` `114543d9f19a6bfeb5bca43686aea173d38755a3db1f2eec112647ae92c6f544`<br>`tzdata_2026b.orig.tar.gz.asc` `b69ac9d9c926cb5ef80ab0b4bbc2a462eb9b4b36167e4aac649d87b744f7ca8b`<br>`tzdata_2026b-0+deb12u1.debian.tar.xz` `a5b70ea0b5ffe7905e0e8bb5ac45196131ce235d3a0cf5665b4b3ac96caa2c35` |
