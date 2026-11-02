"""
benchmarks/ -- Phase 7 performance measurement harness.

Additive by construction: nothing in this package is imported by
client/, cloud/, tests/ or web/, and nothing in it modifies them. It
imports the real client package as a library and drives the real
cloud/cloud_app.py process over real HTTP, so what it measures is the
shipped system rather than a re-implementation of it.

The root pytest run is unaffected: pytest.ini pins
`testpaths = tests`, so benchmarks/tests/ (this package's own
self-tests) is only collected when a path under benchmarks/ is passed
explicitly.
"""
