uses libmagic to detect the sample’s file type and pick a mutation engine
avoids creating disk files — uses Linux in-memory file descriptors (memfd) and /proc/self/fd/<n> so the target sees a filename but nothing is written to disk
forks an isolated child for each run (stateless in-memory reset) — no files created on disk
This is Linux-only (uses memfd_create).

You’ll need libmagic (libmagic-dev / file dev headers) to compile

use concise naming for functions and varable