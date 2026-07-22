# Sample Bootstrap-Window Result (2026-07-22)

Homelab Linux 6.6.68, five counterbalanced repetitions per agent mode, one
no-agent control, six seconds per workload:

| Mode | Median first-signal window | P95 | Standard deviation |
| --- | ---: | ---: | ---: |
| 2-second polling | 1148.131 ms | 1216.842 ms | 105.194 ms |
| Event-driven discovery | 0.463 ms | 0.487 ms | 0.016 ms |

Median reduction: 1147.667 ms, or 99.959648%. All inotify failure, overflow,
watch-limit, map-apply, and exec-source loss gates were zero. Full method and
per-run values are in
`documentation/proof/bootstrap-window-20260722/`.
