# D0 Rust archive-in-Git rehearsal

Basis:`pkgre-rust@f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b` | run:2026-08-26T11:51:34Z..2026-08-26T11:51:53Z | filesystem:`tmpfs` | Git:`2.54.0` | purpose:verify all 747 declared Rust archives,then measure ordinary-Git import,pack,bare clone,fixed-ref fetch,checkout,and independent rehash behavior.

Artifacts:`download_archives.py`+`git_rehearsal.py`=rehearsal programs;`downloads.json`=exact catalog manifest;`download-results.json`=per-object retrieval+verification evidence;`download-summary.json`=bounded aggregate;`failures.json`=`[]`;`git-metrics.json`=Git/storage timings+sizes+integrity;`checkout-timing.json`=separate checkout amplification measurement;`verify-pack.txt`=`git verify-pack -v` capture;`SHA256SUMS`=artifact digest manifest.

Result:747/747 routes+unique SHA-256 objects verified;raw archive bytes=129833713;packed repository apparent bytes=129497688;bare repository apparent bytes=129367206;repository+checkout peak apparent bytes=259463968;strict fsck+checkout rehash passed. Measurements are one-host feasibility evidence,not production quota,performance,or durability guarantees.
