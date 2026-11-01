# Marcyrl threat database

Known-bad URLs and hosts (phishing / malware), rebuilt every day by GitHub Actions and published on GitHub Pages
as small hashed shard files. It is queried by the Marcyrl Cybersecurity Scanner (Apps Script).

- `build.py`: downloads the enabled sources, normalizes the URLs, hashes them (SHA-256) and writes `site/db/{u,h}/xx.txt`.
- `.github/workflows/update.yml`: runs `build.py` daily and deploys `site/` to Pages. You can also run it by hand from the Actions tab.
- A source that fails or looks broken makes the run fail, so the previously published database stays online.
- Enable more sources in `SOURCES` (top of `build.py`) only after checking their terms of use.

Data sources: Phishing.Database (MIT license), community-maintained, no guarantees.
This database only lists known-bad entries. A URL that is not listed is *unknown*, not safe.
