# Lancet Dataset — Audit Tracker

Each case's Lancet output needs two levels of review:
- **Agent**: automated analysis (detection counts, key functions, FP/TP classification)
- **Human**: manual review of detection quality, exploit chain correspondence, FP/FN judgment

Status: `—` = not reviewed, `✓` = reviewed, `⚠` = reviewed with issues noted

## CVE Cases (Tier 1–3)

| # | Case | Target | Lines | UAF | Agent | Human | Notes |
|---|------|--------|------:|----:|:-----:|:-----:|-------|
| 1 | `CVE-2019-11932_whatsapp` | WhatsApp (libpl_droidsonroids_gif) | 133 | 76 | ✓ | — |  |
| 2 | `CVE-2020-9273_proftpd` | ProFTPD | 7 | 0 | ⚠ | — |  |
| 3 | `CVE-2021-3156_sudo` | sudo | 5 | 0 | ⚠ | — |  |
| 4 | `CVE-2024-12084_rsync` | rsync | 86 | 0 | ⚠ | — |  |
| 5 | `CVE-2024-4323_fluentbit` | Fluent Bit | 7220 | 1519 | ✓ | — |  |
| 6 | `CVE-2024-6387_openssh` | OpenSSH | 6 | 0 | ⚠ | — |  |
| 7 | `CVE-2025-3277_sqlite` | SQLite | 10985 | 6394 | ✓ | — |  |
| 8 | `CVE-2025-49844_redis` | Redis | 602 | 142 | ⚠ | — | FP:HIGH — see notes |
| 9 | `CVE-2026-32746_telnetd` | GNU inetutils telnetd | 423 | 313 | ⚠ | — |  |
| 10 | `CVE-2026-39210_ffmpeg` | FFmpeg | 322 | 23 | ✓ | — |  |
| 11 | `CVE-2026-39211_ffmpeg` | FFmpeg | 81 | 0 | ✓ | — |  |
| 12 | `CVE-2026-39212_ffmpeg` | FFmpeg | 235 | 19 | ✓ | — |  |
| 13 | `CVE-2026-39213_ffmpeg` | FFmpeg | 312 | 23 | ✓ | — | FP:249 |
| 14 | `CVE-2026-39214_ffmpeg` | FFmpeg | 235 | 19 | ✓ | — |  |
| 15 | `CVE-2026-39215_ffmpeg` | FFmpeg | 81 | 0 | ✓ | — |  |
| 16 | `CVE-2026-39216_ffmpeg` | FFmpeg | 235 | 19 | ✓ | — |  |
| 17 | `CVE-2026-39217_ffmpeg` | FFmpeg | 317 | 24 | ✓ | — | FP:248 |
| 18 | `CVE-2026-39218_ffmpeg` | FFmpeg | 347 | 37 | ✓ | — | FP:306 |

## how2heap Cases

| # | Case | Lines | UAF | Agent | Human | Notes |
|---|------|------:|----:|:-----:|:-----:|-------|
| 19 | `h2h_decrypt_safe_linking` | 23 | 2 | ✓ | — | |
| 20 | `h2h_fastbin_dup` | 7 | 0 | ✓ | — | |
| 21 | `h2h_fastbin_dup_consolidate` | 5 | 0 | ⚠ | — | |
| 22 | `h2h_fastbin_dup_into_stack` | 7 | 0 | ✓ | — | |
| 23 | `h2h_fastbin_reverse_into_tcache` | 10 | 1 | ✓ | — | |
| 24 | `h2h_house_of_botcake` | 5 | 0 | ✓ | — | |
| 25 | `h2h_house_of_einherjar` | 10 | 0 | ✓ | — | |
| 26 | `h2h_house_of_lore` | 28 | 5 | ✓ | — | |
| 27 | `h2h_house_of_mind_fastbin` | 20 | 0 | ✓ | — | |
| 28 | `h2h_house_of_spirit` | 6 | 0 | ⚠ | — | |
| 29 | `h2h_house_of_tangerine` | 11 | 0 | ✓ | — | |
| 30 | `h2h_house_of_water` | 54 | 9 | ✓ | — | |
| 31 | `h2h_large_bin_attack` | 12 | 1 | ✓ | — | |
| 32 | `h2h_mmap_overlapping_chunks` | 13 | 0 | ✓ | — | |
| 33 | `h2h_overlapping_chunks` | 23 | 0 | ✓ | — | |
| 34 | `h2h_poison_null_byte` | 19 | 3 | ✓ | — | |
| 35 | `h2h_safe_link_double_protect` | 21 | 3 | ✓ | — | |
| 36 | `h2h_sysmalloc_int_free` | 6 | 0 | ✓ | — | |
| 37 | `h2h_tcache_house_of_spirit` | 6 | 0 | ✓ | — | |
| 38 | `h2h_tcache_metadata_hijacking` | 8 | 0 | ✓ | — | |
| 39 | `h2h_tcache_metadata_poisoning` | 6 | 0 | ✓ | — | |
| 40 | `h2h_tcache_poisoning` | 12 | 1 | ✓ | — | |
| 40 | `h2h_tcache_relative_write` | 18 | 2 | ✓ | — | |
| 41 | `h2h_tcache_stashing_unlink_attack` | 7 | 0 | ⚠ | — | |
| 42 | `h2h_unsafe_unlink` | 15 | 0 | ✓ | — | |

## OSS-Fuzz Cases

| # | Case | Target | Lines | UAF | Agent | Human | Notes |
|---|------|--------|------:|----:|:-----:|:-----:|-------|
| 43 | `ossfuzz_osv_2017_22` | openjpeg | 5428 | 1488 | ✓ | — |  |
| 44 | `ossfuzz_osv_2017_35` | openjpeg | 8877 | 2690 | ✓ | — |  |
| 45 | `ossfuzz_osv_2017_41` | libpng | 2801 | 1647 | ✓ | — |  |
| 46 | `ossfuzz_osv_2018_109` | openssl | 17004 | 8575 | ✓ | — |  |
| 47 | `ossfuzz_osv_2018_130` | libarchive | 1594 | 757 | ✓ | — |  |
| 48 | `ossfuzz_osv_2018_161` | harfbuzz | 81 | 14 | ✓ | — |  |
| 49 | `ossfuzz_osv_2018_170` | unknown | 3415 | 1852 | ✓ | — |  |
| 50 | `ossfuzz_osv_2018_2` | libgit2 | 1830 | 544 | ✓ | — |  |
| 51 | `ossfuzz_osv_2018_247` | unknown | 1945 | 256 | ✓ | — |  |
| 52 | `ossfuzz_osv_2018_252` | unknown | 1945 | 256 | ✓ | — |  |
| 53 | `ossfuzz_osv_2018_58` | libgit2 | 1766 | 534 | ✓ | — |  |
| 54 | `ossfuzz_osv_2020_1042` | openh264 | 1922 | 1335 | ✓ | — |  |
| 55 | `ossfuzz_osv_2020_1054` | wabt | 1263 | 697 | ✓ | — |  |
| 56 | `ossfuzz_osv_2020_1076` | re2 | 16845 | 8958 | ✓ | — |  |
| 57 | `ossfuzz_osv_2020_1094` | re2 | 17759 | 9530 | ✓ | — |  |
| 58 | `ossfuzz_osv_2020_1113` | unknown | 3139 | 2423 | ✓ | — |  |
| 59 | `ossfuzz_osv_2020_1136` | unknown | 1097 | 333 | ✓ | — |  |
| 60 | `ossfuzz_osv_2020_1148` | unknown | 1036 | 344 | ✓ | — |  |
| 61 | `ossfuzz_osv_2020_1245` | unknown | 857 | 289 | ✓ | — |  |
| 62 | `ossfuzz_osv_2020_1472` | unknown | 2001 | 1410 | ✓ | — |  |
| 63 | `ossfuzz_osv_2020_150` | wabt | 1248 | 690 | ✓ | — |  |
| 64 | `ossfuzz_osv_2020_160` | re2 | 17129 | 8957 | ✓ | — |  |
| 65 | `ossfuzz_osv_2020_1623` | unknown | 358 | 86 | ✓ | — |  |
| 66 | `ossfuzz_osv_2020_1629` | wabt | 7184 | 3653 | ✓ | — |  |
| 67 | `ossfuzz_osv_2020_1735` | unknown | 11027 | 5112 | ✓ | — |  |
| 68 | `ossfuzz_osv_2020_1741` | unknown | 11716 | 5902 | ✓ | — |  |
| 69 | `ossfuzz_osv_2020_1762` | unknown | 11216 | 5235 | ✓ | — |  |
| 70 | `ossfuzz_osv_2020_1777` | unknown | 13000 | 6090 | ✓ | — |  |
| 71 | `ossfuzz_osv_2020_1782` | libxml2 | 4882 | 1400 | ✓ | — |  |
| 72 | `ossfuzz_osv_2020_1792` | libxml2 | 5051 | 1551 | ✓ | — |  |
| 73 | `ossfuzz_osv_2020_1805` | libxml2 | 5066 | 1553 | ✓ | — |  |
| 74 | `ossfuzz_osv_2020_1847` | openh264 | 2213 | 1494 | ✓ | — |  |
| 75 | `ossfuzz_osv_2020_1897` | unknown | 783 | 392 | ✓ | — |  |
| 76 | `ossfuzz_osv_2020_1923` | unknown | 999 | 335 | ✓ | — |  |
| 77 | `ossfuzz_osv_2020_2000` | unknown | 410 | 92 | ✓ | — |  |
| 78 | `ossfuzz_osv_2020_2060` | openssl | 8 | 0 | ✓ | — | 0-UAF |
| 79 | `ossfuzz_osv_2020_2061` | openh264 | 2216 | 1496 | ✓ | — |  |
| 80 | `ossfuzz_osv_2020_2080` | unknown | 189 | 144 | ✓ | — |  |
| 81 | `ossfuzz_osv_2020_2108` | unknown | 1443 | 978 | ✓ | — |  |
| 82 | `ossfuzz_osv_2020_2119` | unknown | 1846 | 1082 | ✓ | — |  |
| 83 | `ossfuzz_osv_2020_2171` | openssl | 11 | 0 | ✓ | — | 0-UAF |
| 84 | `ossfuzz_osv_2020_2192` | unknown | 133 | 85 | ✓ | — |  |
| 85 | `ossfuzz_osv_2020_225` | unknown | 1091 | 624 | ✓ | — |  |
| 86 | `ossfuzz_osv_2020_2299` | openssl | 1129 | 582 | ✓ | — | Docker |
| 87 | `ossfuzz_osv_2020_238` | libarchive | 1617 | 717 | ✓ | — |  |
| 88 | `ossfuzz_osv_2020_252` | json-c | 658 | 0 | ✓ | — | 0-UAF |
| 89 | `ossfuzz_osv_2020_255` | unknown | 1137 | 633 | ✓ | — |  |
| 90 | `ossfuzz_osv_2020_263` | unknown | 6734 | 3643 | ✓ | — |  |
| 91 | `ossfuzz_osv_2020_280` | c-ares | 63 | 26 | ✓ | — |  |
| 92 | `ossfuzz_osv_2020_313` | libgit2 | 2010 | 1316 | ✓ | — |  |
| 93 | `ossfuzz_osv_2020_315` | re2 | 17054 | 8934 | ✓ | — |  |
| 94 | `ossfuzz_osv_2020_386` | openssl | 3810 | 2072 | ✓ | — |  |
| 95 | `ossfuzz_osv_2020_393` | re2 | 18209 | 9564 | ✓ | — |  |
| 96 | `ossfuzz_osv_2020_405` | zstd | 359 | 208 | ✓ | — |  |
| 97 | `ossfuzz_osv_2020_407` | unknown | 484 | 319 | ✓ | — |  |
| 98 | `ossfuzz_osv_2020_429` | zstd | 625 | 248 | ✓ | — |  |
| 99 | `ossfuzz_osv_2020_522` | re2 | 16848 | 9048 | ✓ | — |  |
| 100 | `ossfuzz_osv_2020_530` | c-ares | 106 | 50 | ✓ | — |  |
| 101 | `ossfuzz_osv_2020_624` | lz4 | 214 | 146 | ✓ | — |  |
| 102 | `ossfuzz_osv_2020_625` | re2 | 18219 | 9570 | ✓ | — |  |
| 103 | `ossfuzz_osv_2020_64` | re2 | 17019 | 8712 | ✓ | — |  |
| 104 | `ossfuzz_osv_2020_649` | unknown | 569 | 105 | ✓ | — |  |
| 105 | `ossfuzz_osv_2020_68` | c-ares | 660 | 476 | ✓ | — |  |
| 106 | `ossfuzz_osv_2020_688` | unknown | 1542 | 724 | ✓ | — |  |
| 107 | `ossfuzz_osv_2020_722` | re2 | 16932 | 8998 | ✓ | — |  |
| 108 | `ossfuzz_osv_2020_744` | mruby | 3019 | 1379 | ✓ | — |  |
| 109 | `ossfuzz_osv_2020_881` | re2 | 18583 | 8747 | ✓ | — |  |
| 110 | `ossfuzz_osv_2021_1045` | mruby | 2433 | 924 | ✓ | — |  |
| 111 | `ossfuzz_osv_2021_1117` | libxml2 | 2937 | 1035 | ✓ | — |  |
| 112 | `ossfuzz_osv_2021_1171` | unknown | 4733 | 765 | ✓ | — |  |
| 113 | `ossfuzz_osv_2021_1195` | unknown | 874 | 556 | ✓ | — |  |
| 114 | `ossfuzz_osv_2021_1196` | unknown | 788 | 490 | ✓ | — |  |
| 115 | `ossfuzz_osv_2021_1202` | unknown | 963 | 529 | ✓ | — |  |
| 116 | `ossfuzz_osv_2021_1218` | mruby | 2219 | 730 | ✓ | — |  |
| 117 | `ossfuzz_osv_2021_1221` | unknown | 493 | 305 | ✓ | — |  |
| 118 | `ossfuzz_osv_2021_1229` | unknown | 12 | 0 | ✓ | — | 0-UAF |
| 119 | `ossfuzz_osv_2021_1241` | wabt | 4794 | 2567 | ✓ | — |  |
| 120 | `ossfuzz_osv_2021_1330` | unknown | 727 | 452 | ✓ | — |  |
| 121 | `ossfuzz_osv_2021_1340` | mruby | 2293 | 727 | ✓ | — |  |
| 122 | `ossfuzz_osv_2021_1400` | unknown | 855 | 432 | ✓ | — |  |
| 123 | `ossfuzz_osv_2021_1500` | re2 | 21492 | 9778 | ✓ | — |  |
| 124 | `ossfuzz_osv_2021_1521` | unknown | 1652 | 942 | ✓ | — |  |
| 125 | `ossfuzz_osv_2021_1625` | curl | 176 | 77 | ✓ | — |  |
| 126 | `ossfuzz_osv_2021_1627` | unknown | 2051 | 1010 | ✓ | — |  |
| 127 | `ossfuzz_osv_2021_1674` | unknown | 1356 | 772 | ✓ | — |  |
| 128 | `ossfuzz_osv_2021_1678` | unknown | 27 | 0 | ✓ | — | 0-UAF |
| 129 | `ossfuzz_osv_2021_1695` | unknown | 12 | 0 | ✓ | — | 0-UAF |
| 130 | `ossfuzz_osv_2021_205` | unknown | 7316 | 1661 | ✓ | — |  |
| 131 | `ossfuzz_osv_2021_25` | unknown | 1156 | 69 | ✓ | — |  |
| 132 | `ossfuzz_osv_2021_273` | unknown | 843 | 368 | ✓ | — |  |
| 133 | `ossfuzz_osv_2021_281` | unknown | 12 | 0 | ✓ | — | 0-UAF |
| 134 | `ossfuzz_osv_2021_305` | unknown | 237 | 106 | ✓ | — |  |
| 135 | `ossfuzz_osv_2021_308` | unknown | 12 | 0 | ✓ | — | 0-UAF |
| 136 | `ossfuzz_osv_2021_333` | unknown | 12 | 0 | ✓ | — | 0-UAF |
| 137 | `ossfuzz_osv_2021_349` | unknown | 12 | 0 | ✓ | — | 0-UAF |
| 138 | `ossfuzz_osv_2021_373` | wabt | 5355 | 2733 | ✓ | — |  |
| 139 | `ossfuzz_osv_2021_392` | mruby | 2526 | 883 | ✓ | — |  |
| 140 | `ossfuzz_osv_2021_40` | libxml2 | 3032 | 1080 | ✓ | — |  |
| 141 | `ossfuzz_osv_2021_418` | systemd | 337 | 17 | ✓ | — |  |
| 142 | `ossfuzz_osv_2021_427` | unknown | 2841 | 1447 | ✓ | — |  |
| 143 | `ossfuzz_osv_2021_447` | unknown | 6272 | 1080 | ✓ | — |  |
| 144 | `ossfuzz_osv_2021_455` | unknown | 11348 | 5809 | ✓ | — |  |
| 145 | `ossfuzz_osv_2021_512` | unknown | 7280 | 1658 | ✓ | — |  |
| 146 | `ossfuzz_osv_2021_520` | unknown | 12 | 0 | ✓ | — | 0-UAF |
| 147 | `ossfuzz_osv_2021_609` | unknown | 13 | 0 | ✓ | — | 0-UAF |
| 148 | `ossfuzz_osv_2021_924` | unknown | 407 | 214 | ✓ | — |  |
| 149 | `ossfuzz_osv_2021_925` | unknown | 78 | 45 | ✓ | — |  |
| 150 | `ossfuzz_osv_2021_927` | unknown | 85 | 53 | ✓ | — |  |
| 151 | `ossfuzz_osv_2021_932` | unknown | 234 | 120 | ✓ | — |  |
| 152 | `ossfuzz_osv_2021_934` | unknown | 849 | 511 | ✓ | — |  |
| 153 | `ossfuzz_osv_2021_935` | unknown | 449 | 231 | ✓ | — |  |
| 154 | `ossfuzz_osv_2021_979` | unknown | 784 | 373 | ✓ | — |  |
| 155 | `ossfuzz_osv_2022_1046` | curl | 7950 | 3987 | ✓ | — |  |
| 156 | `ossfuzz_osv_2022_105` | unknown | 509 | 396 | ✓ | — |  |
| 157 | `ossfuzz_osv_2022_1078` | unknown | 4456 | 2299 | ✓ | — |  |
| 158 | `ossfuzz_osv_2022_1087` | re2 | 21470 | 9655 | ✓ | — |  |
| 159 | `ossfuzz_osv_2022_1093` | unknown | 2565 | 1337 | ✓ | — |  |
| 160 | `ossfuzz_osv_2022_1098` | unknown | 712 | 367 | ✓ | — |  |
| 161 | `ossfuzz_osv_2022_1223` | unknown | 517 | 0 | ✓ | — | 0-UAF |
| 162 | `ossfuzz_osv_2022_133` | unknown | 1060 | 665 | ✓ | — |  |
| 163 | `ossfuzz_osv_2022_147` | unknown | 112 | 81 | ✓ | — |  |
| 164 | `ossfuzz_osv_2022_220` | libxml2 | 4155 | 566 | ✓ | — |  |
| 165 | `ossfuzz_osv_2022_24` | openssl | 725 | 0 | ⚠ | — | 0-UAF |
| 166 | `ossfuzz_osv_2022_258` | unknown | 868 | 379 | ✓ | — |  |
| 167 | `ossfuzz_osv_2022_347` | libxml2 | 570 | 222 | ✓ | — |  |
| 168 | `ossfuzz_osv_2022_393` | mruby | 4077 | 1192 | ✓ | — |  |
| 169 | `ossfuzz_osv_2022_416` | openjpeg | 4846 | 1067 | ✓ | — |  |
| 170 | `ossfuzz_osv_2022_468` | unknown | 568 | 352 | ✓ | — |  |
| 171 | `ossfuzz_osv_2022_472` | systemd | 462 | 102 | ✓ | — |  |
| 172 | `ossfuzz_osv_2022_549` | lz4 | 199 | 41 | ✓ | — |  |
| 173 | `ossfuzz_osv_2022_550` | mruby | 3010 | 1101 | ✓ | — |  |
| 174 | `ossfuzz_osv_2022_551` | unknown | 17 | 2 | ✓ | — |  |
| 175 | `ossfuzz_osv_2022_572` | unknown | 90 | 54 | ✓ | — |  |
| 176 | `ossfuzz_osv_2022_598` | re2 | 21172 | 9594 | ✓ | — |  |
| 177 | `ossfuzz_osv_2022_61` | libxml2 | 418 | 161 | ✓ | — |  |
| 178 | `ossfuzz_osv_2022_615` | lcms | 4 | 0 | ✓ | — | 0-UAF |
| 179 | `ossfuzz_osv_2022_62` | libxml2 | 449 | 169 | ✓ | — |  |
| 180 | `ossfuzz_osv_2022_647` | lcms | 2465 | 1332 | ✓ | — |  |
| 181 | `ossfuzz_osv_2022_698` | unknown | 1542 | 590 | ✓ | — |  |
| 182 | `ossfuzz_osv_2022_810` | unknown | 1211 | 357 | ✓ | — |  |
| 183 | `ossfuzz_osv_2022_861` | unknown | 317 | 96 | ✓ | — |  |
| 184 | `ossfuzz_osv_2022_904` | unknown | 12177 | 3323 | ✓ | — |  |
| 185 | `ossfuzz_osv_2023_1069` | unknown | 568 | 101 | ✓ | — |  |
| 186 | `ossfuzz_osv_2023_11` | unknown | 118 | 92 | ✓ | — |  |
| 187 | `ossfuzz_osv_2023_1117` | lcms | 14 | 3 | ✓ | — |  |
| 188 | `ossfuzz_osv_2023_1164` | lcms | 4 | 0 | ✓ | — | 0-UAF |
| 189 | `ossfuzz_osv_2023_118` | mruby | 3982 | 1222 | ✓ | — |  |
| 190 | `ossfuzz_osv_2023_1247` | re2 | 20563 | 8979 | ✓ | — |  |
| 191 | `ossfuzz_osv_2023_1365` | unknown | 25 | 15 | ✓ | — |  |
| 192 | `ossfuzz_osv_2023_205` | p11-kit | 5 | 0 | ✓ | — | 0-UAF |
| 193 | `ossfuzz_osv_2023_31` | zstd | 1215 | 328 | ✓ | — |  |
| 194 | `ossfuzz_osv_2023_321` | unknown | 1123 | 457 | ✓ | — |  |
| 195 | `ossfuzz_osv_2023_326` | systemd | 297 | 0 | ✓ | — | 0-UAF |
| 196 | `ossfuzz_osv_2023_356` | libxml2 | 2591 | 936 | ✓ | — |  |
| 197 | `ossfuzz_osv_2023_358` | openssl | 13 | 0 | ✓ | — | 0-UAF |
| 198 | `ossfuzz_osv_2023_382` | wabt | 19291 | 9612 | ✓ | — |  |
| 199 | `ossfuzz_osv_2023_451` | openssl | 67 | 0 | ✓ | — | 0-UAF |
| 200 | `ossfuzz_osv_2023_458` | harfbuzz | 8543 | 4216 | ✓ | — |  |
| 201 | `ossfuzz_osv_2023_460` | openssl | 286 | 0 | ⚠ | — | 0-UAF |
| 202 | `ossfuzz_osv_2023_499` | mruby | 3440 | 1036 | ✓ | — |  |
| 203 | `ossfuzz_osv_2023_546` | unknown | 772 | 317 | ✓ | — |  |
| 204 | `ossfuzz_osv_2023_56` | pcre2 | 221 | 0 | ✓ | — | 0-UAF |
| 205 | `ossfuzz_osv_2023_56_libgit2` | libgit2 | 3496 | 2608 | ✓ | — |  |
| 206 | `ossfuzz_osv_2023_66` | systemd | 299 | 0 | ✓ | — | 0-UAF |
| 207 | `ossfuzz_osv_2023_67` | systemd | 299 | 0 | ✓ | — | 0-UAF |
| 208 | `ossfuzz_osv_2023_673` | pcre2 | 2757 | 2087 | ✓ | — |  |
| 209 | `ossfuzz_osv_2023_674` | pcre2 | 434 | 0 | ✓ | — | 0-UAF |
| 210 | `ossfuzz_osv_2023_90` | unknown | 3255 | 1809 | ✓ | — |  |
| 211 | `ossfuzz_osv_2023_989` | re2 | 20477 | 8914 | ✓ | — |  |
| 212 | `ossfuzz_osv_2024_102` | mruby | 2825 | 910 | ✓ | — |  |
| 213 | `ossfuzz_osv_2024_1206` | unknown | 994 | 536 | ✓ | — |  |
| 214 | `ossfuzz_osv_2024_1230` | unknown | 1381 | 782 | ✓ | — |  |
| 215 | `ossfuzz_osv_2024_20` | unknown | 103 | 0 | ✓ | — | 0-UAF |
| 216 | `ossfuzz_osv_2024_314` | openssl | 248 | 0 | ✓ | — | 0-UAF |
| 217 | `ossfuzz_osv_2024_550` | unknown | 1604 | 857 | ✓ | — |  |


## how2heap glibc-2.35 Cases

| # | Case | Lines | UAF | Agent | Human | Notes |
|---|------|------:|----:|:-----:|:-----:|-------|
| 236 | `h2h_235_decrypt_safe_linking` | 26 | 2 | — | — | glibc-2.35 |
| 237 | `h2h_235_fastbin_dup` | 36 | 0 | — | — | glibc-2.35 |
| 238 | `h2h_235_fastbin_dup_consolidate` | 25 | 0 | — | — | glibc-2.35 |
| 239 | `h2h_235_fastbin_dup_into_stack` | 35 | 0 | — | — | glibc-2.35 |
| 240 | `h2h_235_fastbin_reverse_into_tcache` | 48 | 1 | — | — | glibc-2.35 |
| 241 | `h2h_235_house_of_botcake` | 39 | 1 | — | — | glibc-2.35 |
| 242 | `h2h_235_house_of_einherjar` | 42 | 1 | — | — | glibc-2.35 |
| 243 | `h2h_235_house_of_lore` | 51 | 5 | — | — | glibc-2.35 |
| 244 | `h2h_235_house_of_mind_fastbin` | 444 | 0 | — | — | glibc-2.35 |
| 245 | `h2h_235_house_of_spirit` | 22 | 0 | — | — | glibc-2.35 |
| 246 | `h2h_235_house_of_tangerine` | 23 | 0 | — | — | glibc-2.35 |
| 247 | `h2h_235_house_of_water` | 86 | 6 | — | — | glibc-2.35 |
| 248 | `h2h_235_large_bin_attack` | 23 | 1 | — | — | glibc-2.35 |
| 249 | `h2h_235_mmap_overlapping_chunks` | 24 | 0 | — | — | glibc-2.35 |
| 250 | `h2h_235_overlapping_chunks` | 16 | 0 | — | — | glibc-2.35 |
| 251 | `h2h_235_poison_null_byte` | 43 | 3 | — | — | glibc-2.35 |
| 252 | `h2h_235_safe_link_double_protect` | 26 | 0 | — | — | glibc-2.35 |
| 253 | `h2h_235_sysmalloc_int_free` | 12 | 0 | — | — | glibc-2.35 |
| 254 | `h2h_235_tcache_house_of_spirit` | 10 | 0 | — | — | glibc-2.35 |
| 255 | `h2h_235_tcache_metadata_poisoning` | 9 | 0 | — | — | glibc-2.35 |
| 256 | `h2h_235_tcache_poisoning` | 18 | 1 | — | — | glibc-2.35 |
| 257 | `h2h_235_tcache_relative_write` | 28 | 2 | — | — | glibc-2.35 |
| 258 | `h2h_235_tcache_stashing_unlink_attack` | 32 | 1 | — | — | glibc-2.35 |
| 259 | `h2h_235_unsafe_unlink` | 15 | 0 | — | — | glibc-2.35 |

## Summary

| Category | Cases | Agent Reviewed (final) | Human Reviewed |
|----------|------:|:----------------------:|:--------------:|
| CVE | 18 | 18/18 (12✓ 6⚠) | 0/18 |
| how2heap | 25 | 25/25 (22✓ 3⚠) | 0/25 |
| OSS-Fuzz | 175 | 175/175 (173✓ 2⚠) | 0/175 |
| **Total** | **242** | **218/242 (207✓ 11⚠ 24—)** | **0/242** |

## Detailed FP/FN Analysis

### Global Detection Quality

| Tier | TP | FP | Precision | Notes |
|------|---:|---:|----------:|-------|
| CVE (excl. Redis) | 34,864 | 13,959 | 71.4% | Excl. Redis+FFmpeg init → ~99.9% |
| CVE (Redis only) | 0 | 21,841 | 0% | jemalloc FP (T1 in TODO) |
| how2heap | 162 | 0 | **100%** | Zero false positives |
| OSS-Fuzz (UAF bugs) | — | — | 89.7% | Core target domain |
| OSS-Fuzz (OOB bugs) | — | — | 6.5% | Cascading UAF from OOB |
| OSS-Fuzz (overall) | 177,792 | 415,546 | 30.0% | OOB cases dominate FP |
| **Total** | **212,818** | **451,346** | **32.0%** | |

### FP Sources (ranked by impact)

| # | Source | FP Count | % of total | Affected Cases | Root Cause | Fix |
|---|--------|-------:|----------:|---------------:|------------|-----|
| 1 | UAF on OOB bugs (cascading) | 396,742 | 87.9% | 84 OSS-Fuzz | OOB enters adjacent freed region → reports UAF | Bounds-aware check or OOB→UAF reclassification |
| 2 | Redis jemalloc internals | 21,841 | 4.8% | 1 CVE | jemalloc statically linked, internal ops = UAF FP | T1: allocator code-range exemption |
| 3 | FFmpeg UNTRUSTEDPTRDEREF | ~13,959 | 3.1% | 9 CVE | Init code pointer loads before tracking | More pre-tracking suppression |
| 4 | UNINITIALIZED residual | 4,827 | 1.1% | ~171 | Writes via unhooked functions (sprintf, fread, etc.) | Additional semantic hooks |
| 5 | TAINT (alloc/free churn) | 2,018 | 0.4% | 41 | Normal reuse cycle stale vo | Refine FreeBefore/MallocAfter pre-mark |
| 6 | Other (CROSSBOUNDARY, INTRA_OBJECT) | ~12,959 | 2.9% | various | Case-specific | — |

**Key insight**: Source #1 alone accounts for 88% of all FP. Fixing it would raise overall precision from 32% to ~80%.

### FN Cases (11 cases, 6 patterns)

| Pattern | Cases | Root Cause | Fix |
|---------|-------|------------|-----|
| Cross-process blind spot | `CVE-2020-9273_proftpd`, `CVE-2021-3156_sudo` | PIN instruments one process; server-side UAF in forked child invisible | PIN `--follow_execv` or in-process harness |
| Same-owner OOB write | `CVE-2021-3156_sudo`, `CVE-2024-12084_rsync` | Write uses owning pointer → ownership model sees no violation | Bounds-aware ownership (track alloc size) |
| glibc-internal operations | `h2h_fastbin_dup_consolidate`, `h2h_house_of_spirit`, `h2h_tcache_stashing_unlink_attack` | Technique traverses normal glibc free/malloc path — no app-level ownership violation | Hook glibc internals or out-of-scope |
| Custom allocator wrapper | `ossfuzz_osv_2023_358` (wolfCrypt) | `wolfCrypt_custom_free` wraps `free()` — PIN hooks miss wrapper | Hook custom free wrapper |
| Shallow UAF window | `ossfuzz_osv_2023_326`, `ossfuzz_osv_2023_67` (mosquitto) | Freed object accessed briefly before tracking catches it | Finer-grained tracking |
| Race condition | `CVE-2024-6387_openssh` | SIGALRM race impossible under PIN's 10000x slowdown | Inherent PIN limitation |

### Precision by Vulnerability Type (OSS-Fuzz)

| Bug Type | Cases | Precision | Notes |
|----------|------:|----------:|-------|
| UAF | 19 | 89.7% | Lancet's core capability |
| Invalid free | 3 | 95.6% | Clean signal |
| Double-free | 3 | 86.8% | Direct ownership violation |
| Unknown | 46 | 87.8% | Mixed bug types |
| Heap-OOB | 84 | 6.5% | Cascading UAF FP dominates |
| Stack-OOB | 12 | 5.6% | Same cascading pattern |
| Global-OOB | 3 | 9.8% | Same pattern |
| Null deref | 4 | 1.6% | Out of scope for ownership model |
| Uninitialized | 1 | 0.1% | Out of scope |

### ⚠ Cases Detail (11 remaining)

| Case | Issue | Category |
|------|-------|----------|
| `CVE-2020-9273_proftpd` | Server-side UAF in forked child; PIN sees client only | FN: cross-process |
| `CVE-2021-3156_sudo` | Same-owner OOB; harness limited to user_args parsing | FN: same-owner OOB |
| `CVE-2024-12084_rsync` | memcpy stays within single subject; harness partial | FN: bulk memcpy |
| `CVE-2024-6387_openssh` | SIGALRM race untriggerable under PIN | FN: race condition |
| `CVE-2025-49844_redis` | 21K jemalloc FP; exploit startup only | FP: jemalloc |
| `CVE-2026-32746_telnetd` | Harness limited; missing CROSSBOUNDARY on SLC overflow | FN: harness scope |
| `h2h_fastbin_dup_consolidate` | malloc_consolidate inside glibc invisible | FN: glibc-internal |
| `h2h_house_of_spirit` | Fake chunk free traverses normal glibc path | FN: glibc-internal |
| `h2h_tcache_stashing_unlink_attack` | bk corruption + stashing loop inside glibc | FN: glibc-internal |
| `ossfuzz_osv_2022_24` | 0 UAF; TAINT FP only; libssh2 unknown vuln type | FP: TAINT noise |
| `ossfuzz_osv_2023_460` | 0 UAF; null-deref; mostly UNINITIALIZED/TAINT FP | FP: out of scope |
