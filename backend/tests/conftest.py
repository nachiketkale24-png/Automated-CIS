"""
conftest.py — shared pytest configuration.

Each test module uses its OWN engine + session that it declares locally,
and registers it via app.dependency_overrides INSIDE its own fixtures,
not at module level. This prevents cross-file override collisions.

This conftest just ensures the 'app' import doesn't crash and provides
a clean slate between files.
"""
