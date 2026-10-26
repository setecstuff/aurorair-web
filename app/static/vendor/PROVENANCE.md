# Vendored third-party assets — provenance & integrity

These files are served from `app/static/vendor/`. The app loads **no** third-party scripts at
runtime (CSP `script-src 'self'`), so these local copies are the only external code shipped to
browsers. Each JS file below was verified byte-for-byte (SHA-256) against its official upstream
published artifact. Re-verify with: `sha256sum -c vendor.sha256`.

| file | version | upstream (jsDelivr/npm) |
|---|---|---|
| chart.umd.min.js | Chart.js 4.5.1 | npm chart.js@4.5.1 /dist/chart.umd.min.js |
| moment.min.js | Moment.js 2.31.0 | npm moment@2.31.0 /min/moment.min.js |
| vis-data.min.js | vis-data 8.0.5 | npm vis-data@8.0.5 /peer/umd/vis-data.min.js |
| vis-network.min.js (+.css) | vis-network 10.1.2 | npm vis-network@10.1.2 /peer/umd/… |
| vis-timeline-graph2d.min.js (+.css) | vis-timeline 8.5.4 | npm vis-timeline@8.5.4 /peer/umd/… |

Licenses are in `licenses/`. See also the repository [NOTICE](../../../NOTICE).
