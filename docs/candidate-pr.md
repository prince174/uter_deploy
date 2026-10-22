Product unit/API tests and deployment contract checks passed for the recorded source commit.

This PR records a candidate only. It does not publish a deployable release or change customer installations.

Before release: build protected images from this exact commit, scan every image layer for product source/secrets, record real image digests, test clean installation and upgrade from each supported previous release, run functional acceptance, then sign and publish the bundle.
