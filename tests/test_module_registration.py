"""Runtime module registration.

These exist because of a real failure. Stage 6 shipped with 220 passing tests
and `DNSF_ENGINE_MODULES=nrd` still failed at startup with "unknown module".
Every Stage 6 test imported `NewDomainModule` directly, so nothing ever
checked that the module was reachable by the *name* an operator types. The
tests proved the code worked and said nothing about whether it could be
switched on.

The tests below are written generically over `REGISTRY`, so a module added in
a later stage is covered the moment it is registered — and a module that is
implemented but never registered fails here instead of on a demo machine.
"""

import pytest

from config.settings import Settings
from engine.decision import DecisionEngine
from engine.modules import REGISTRY
from engine.modules.base import DetectionModule
from proxy.dns_proxy import build_engine

#: Names an operator must be able to put in DNSF_ENGINE_MODULES, by stage.
#: Add to this as modules land; a name here that is missing from REGISTRY is a
#: shipping defect, not a test to relax.
EXPECTED_MODULES = {
    "null": "Stage 4 reference module",
    "ti": "Stage 5 threat intelligence",
    "nrd": "Stage 6 domain age",
}


def offline_settings(tmp_path, **overrides) -> Settings:
    """Settings that build any module without touching the network or a database.

    A registration test must not depend on a feed being reachable, or it
    stops being a test of registration.
    """
    feed = tmp_path / "feed.txt"
    feed.write_text("controlled.test\n", encoding="utf-8")

    defaults = dict(
        db_enabled=False,
        feed_file=str(feed),
        feed_refresh_s=0.0,     # no background refresh thread
        nrd_refresh_s=0.0,
    )
    defaults.update(overrides)
    return Settings(**defaults)


# -- the registry itself --------------------------------------------------

@pytest.mark.parametrize("name,description", sorted(EXPECTED_MODULES.items()))
def test_each_shipped_module_is_registered(name, description):
    """A module that exists but is not registered cannot be switched on."""
    assert name in REGISTRY, (
        f"{description} is missing from engine.modules.REGISTRY, so "
        f"DNSF_ENGINE_MODULES={name} fails at startup. Available: "
        f"{sorted(REGISTRY)}")


def test_every_registry_entry_is_a_detection_module():
    for name, cls in REGISTRY.items():
        assert isinstance(cls, type), f"REGISTRY[{name!r}] is not a class"
        assert issubclass(cls, DetectionModule), \
            f"REGISTRY[{name!r}] does not implement DetectionModule"


def test_registry_keys_match_module_names():
    """The configured name and the name in evidence rows must agree.

    If they diverge, an operator enables `nrd` and finds evidence attributed
    to something else, and the Stage 16 ablation cannot match a configuration
    to its results.
    """
    for name, cls in REGISTRY.items():
        assert cls.name == name, (
            f"REGISTRY key {name!r} but {cls.__name__}.name is {cls.name!r}")


# -- construction through the real startup path ---------------------------

@pytest.mark.parametrize("name", sorted(EXPECTED_MODULES))
def test_each_module_can_be_built_by_name(name, tmp_path):
    """Exercises exactly what `python -m proxy.dns_proxy` does at startup."""
    engine = build_engine(offline_settings(tmp_path, engine_modules=name))
    try:
        assert isinstance(engine, DecisionEngine)
        assert engine.name == f"engine[{name}]"
        assert [m.name for m in engine.modules] == [name]
    finally:
        engine.close()


def test_every_registered_module_can_be_built(tmp_path):
    """Generic: covers modules added in later stages automatically."""
    for name in sorted(REGISTRY):
        engine = build_engine(offline_settings(tmp_path, engine_modules=name))
        try:
            assert engine.modules, f"building {name!r} produced no module"
        finally:
            engine.close()


def test_modules_can_be_combined(tmp_path):
    """The hybrid arm of the Stage 16 ablation is a comma-separated list."""
    engine = build_engine(offline_settings(tmp_path, engine_modules="ti,nrd"))
    try:
        assert [m.name for m in engine.modules] == ["ti", "nrd"]
        assert engine.name == "engine[ti,nrd]"
    finally:
        engine.close()


def test_a_built_module_actually_scores(tmp_path):
    """Registered and constructible is not enough; it has to run."""
    import time

    from engine.modules.base import QueryContext

    engine = build_engine(offline_settings(tmp_path, engine_modules="ti"))
    try:
        results = engine.evaluate(QueryContext(
            qname="controlled.test", qtype="A", client_id="cid",
            timestamp=time.time()))
        assert len(results) == 1
        assert results[0].module == "ti"
        assert results[0].score == 1.0, "the built module did not match its feed"
    finally:
        engine.close()
