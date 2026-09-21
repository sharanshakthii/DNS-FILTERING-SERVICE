"""Stage 11 tests: the minimal dashboard.

A dashboard is only worth having if what it shows is real. The tests that
matter here are the ones that would catch the failure mode a reviewer would
never spot from looking at the screen: sample data baked into the page, or a
number rendered from a constant rather than from the database.

The page itself is plain HTML and JavaScript with no build step, so these
tests check that it is served correctly and that its source contains no
fabricated content and calls only endpoints that exist.
"""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import api.main as api_main
from tests.conftest import auth_settings_kwargs, sign_in

DASHBOARD = Path(api_main.__file__).resolve().parent.parent / "dashboard" / "index.html"


@pytest.fixture(scope="module")
def source() -> str:
    return DASHBOARD.read_text(encoding="utf-8")


@pytest.fixture
def client(monkeypatch) -> TestClient:
    """Signed in, so the gated dashboard route serves the page."""
    from config.settings import Settings

    monkeypatch.setattr(api_main, "settings",
                        Settings(db_enabled=False, engine_modules="null",
                                 **auth_settings_kwargs()))
    monkeypatch.setattr(api_main, "_authenticator", None)
    monkeypatch.setattr(api_main, "_engine", None)
    return sign_in(TestClient(api_main.app))


# -- it is served ---------------------------------------------------------

def test_the_dashboard_file_exists():
    assert DASHBOARD.is_file(), f"no dashboard at {DASHBOARD}"


def test_the_dashboard_is_served_as_html(client):
    response = client.get("/dashboard/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<title>" in response.text


def test_the_root_redirects_to_the_dashboard(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (301, 302, 307, 308)
    assert response.headers["location"] == "/dashboard/"


def test_mounting_the_dashboard_did_not_shadow_the_api(client):
    """The static mount is last; every endpoint must still answer."""
    assert client.get("/health").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_the_dashboard_is_excluded_from_the_api_schema(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert "/dashboard" not in paths
    assert "/" not in paths


# -- no fabricated data ---------------------------------------------------

def test_the_page_contains_no_hardcoded_decisions(source):
    """The single most important property of this file.

    A dashboard that ships with sample rows looks identical to one reading a
    real database, and would let a demo show numbers nothing produced.
    """
    for invented in ["evil.test", "malware", "blocked.test", "phishing.com",
                     "192.168.", "203.0.113.", "sampleData", "mockData",
                     "fakeDecisions", "DUMMY", "lorem"]:
        assert invented.lower() not in source.lower(), \
            f"the dashboard contains hardcoded content: {invented!r}"


def test_the_page_declares_no_decision_array(source):
    """No literal list of decisions may be assigned anywhere in the script."""
    assert not re.search(r"(decisions|records|rows)\s*=\s*\[\s*\{", source), \
        "a literal array of decision objects is defined in the page"


def test_every_displayed_value_comes_from_a_fetch(source):
    """The page must have no data source other than the API."""
    assert source.count("fetch(") >= 1
    assert "XMLHttpRequest" not in source
    assert "localStorage" not in source, \
        "browser storage would let stale data survive a database reset"


def test_the_page_only_calls_endpoints_that_exist(source, client):
    """Guards against a typo that silently renders an empty dashboard."""
    known = set(client.get("/openapi.json").json()["paths"])
    called = set(re.findall(r'get\("(/[a-z]+)', source))
    called |= set(re.findall(r'send\("(/[a-z]+)', source))
    called |= set(re.findall(r'`(/[a-z]+)/\$\{', source))

    assert called, "no API calls were found in the page"
    for path in called:
        assert any(known_path.startswith(path) for known_path in known), \
            f"the dashboard calls {path}, which the API does not serve"


def test_no_api_host_is_hardcoded(source):
    """It is served from the API's own origin; a hardcoded host would break."""
    assert "http://127.0.0.1:8000" not in source
    assert "http://localhost" not in source


# -- honest presentation --------------------------------------------------

def test_the_page_says_it_is_local_development_only(source):
    assert "Local development only" in source
    assert "no authentication" in source


def test_the_page_does_not_claim_measured_accuracy(source):
    assert "not evaluation metrics" in source
    assert "accuracy has" in source and "not yet been measured" in source
    for overclaim in ["production ready", "production-ready system",
                      "99%", "accuracy:", "detection rate"]:
        assert overclaim.lower() not in source.lower().replace(
            "not production-ready", ""), f"the page claims {overclaim!r}"


def test_policy_verdict_and_enforcement_are_shown_separately(source):
    """A recorded BLOCK and an enforced BLOCK are different facts."""
    assert "Policy verdict" in source
    assert "Would block" in source
    assert "Acted on" in source
    assert "the query was forwarded" in source
    assert "the query was blocked" in source


def test_the_configuration_panel_states_it_does_not_reach_the_proxy(source):
    """Stage 10's limitation must be visible in the UI, not just the API."""
    assert "change this API" in source
    assert "process only" in source
    assert "running DNS proxy is unaffected" in source


def test_the_page_warns_that_weights_are_untuned(source):
    assert "have not been" in source and "tuned" in source


def test_lookup_is_labelled_as_enforcing_nothing(source):
    assert "Nothing is\n        enforced" in source or "enforced" in source
    assert "cannot block anything" in source


# -- empty and error states -----------------------------------------------

def test_an_empty_database_shows_an_empty_state_not_rows(source):
    assert "No decisions stored yet" in source
    assert "Start the DNS proxy and send it a query" in source


def test_failures_are_reported_rather_than_hidden(source):
    assert "Cannot read decisions" in source
    assert "Cannot read the configuration" in source
    assert "Statistics unavailable" in source


# -- safety and accessibility ---------------------------------------------

def test_api_values_are_escaped_before_insertion(source):
    """A domain name is attacker-controlled input rendered into the page."""
    assert "function esc(" in source
    assert "&amp;" in source and "&lt;" in source and "&#39;" in source
    assert source.count("esc(") > 20, "values are being inserted unescaped"


def test_rows_are_keyboard_reachable(source):
    assert 'tabindex="0"' in source
    assert '"Enter"' in source
    assert ":focus-visible" in source


def test_reduced_motion_is_respected(source):
    assert "prefers-reduced-motion" in source


def test_the_page_is_responsive(source):
    assert 'name="viewport"' in source
    assert "@media (max-width" in source


# -- no new dependencies --------------------------------------------------

def test_the_dashboard_pulls_in_no_external_assets(source):
    """No CDN, no framework, no build step: it must work offline."""
    for marker in ["cdn.", "unpkg", "jsdelivr", "googleapis",
                   "react", "vue", "jquery", "bootstrap", "tailwind"]:
        assert marker not in source.lower(), \
            f"the dashboard references {marker!r}"
    assert "<script src=" not in source
    assert "<link rel=\"stylesheet\"" not in source


def test_requirements_gained_nothing_for_stage_11():
    text = (Path(api_main.__file__).resolve().parent.parent
            / "requirements.txt").read_text(encoding="utf-8")
    packages = {line.split("==")[0].split("#")[0].strip().lower()
                for line in text.splitlines()
                if line.strip() and not line.strip().startswith("#")}
    assert packages == {"fastapi", "uvicorn", "pytest", "httpx"}, \
        f"unexpected dependencies: {packages}"


# -- the redesigned console -----------------------------------------------

def test_the_intro_never_gates_the_first_request(source):
    """The animation must not delay data loading.

    A splash screen that blocks fetches would make the console feel slower
    than the system actually is, which is the opposite of what an intro is
    for.
    """
    tail = source.rsplit("startIntro();", 1)[1]
    for call in ["loadStats();", "loadFeed();", "loadMode();"]:
        assert call in tail, f"{call} does not run alongside the intro"


def test_the_intro_can_be_skipped(source):
    assert 'id="skip"' in source
    assert '"Escape"' in source


def test_the_pipeline_rail_names_all_five_stages(source):
    """The rail teaches the pipeline, so it must show the whole pipeline."""
    for stage in ["Query", "Signals", "Aggregation", "Verdict", "Enforcement"]:
        assert f'"{stage}"' in source, f"the rail omits {stage}"


def test_only_transform_and_opacity_are_animated(source):
    """Animating layout properties would make the console janky.

    Checks the transition shorthands actually declared in the stylesheet.
    """
    css = source.split("<style>", 1)[1].split("</style>", 1)[0]
    banned = re.findall(
        r"transition:\s*(?:[^;]*\b)(width|height|top|left|margin|padding)\b[^;]*;",
        css)
    assert not banned, f"layout properties are transitioned: {set(banned)}"


def test_the_weight_track_excludes_uncounted_modules_from_the_width(source):
    """'Not counted' must not be drawn as 'scored zero'.

    An excluded module gets a fixed sliver, never its weight, so it cannot
    appear to widen the denominator the aggregate is divided by.
    """
    assert "c.counted ? Math.max(weight, 0.05) : 0.14" in source
    assert "excluded" in source


def test_unimplemented_modules_are_labelled_and_carry_no_score(source):
    """Future signals must never look like contributing ones."""
    assert "not implemented" in source
    assert "ROADMAP" in source
    # Membership is decided by the live /mode response, not asserted here.
    assert "ROADMAP.filter" in source


def test_an_unenforced_block_is_drawn_differently(source):
    """A recorded BLOCK and an enforced BLOCK are different facts."""
    assert "recorded, not enforced" in source
    assert ".badge.observed" in source
    assert "border-style: dashed" in source


def test_stale_data_is_dimmed_rather_than_discarded(source):
    """Last known state beats a blank panel, provided it is marked stale."""
    assert ".stale" in source
    assert 'classList.add("stale")' in source


def test_the_status_pill_only_animates_on_change(source):
    """A console that twitches every poll teaches you to ignore it."""
    assert "if (connState === state) return;" in source


def test_reduced_motion_disables_the_intro_and_the_sweep(source):
    assert "REDUCED" in source
    assert "if (REDUCED) { enterConsole(); return; }" in source
    assert ".rail.scanning .sweep { animation: none" in source


def test_reduced_motion_still_delivers_the_score(source):
    """The number must arrive even when the count-up is suppressed."""
    assert 'if (REDUCED) { target.textContent = num(to, 3); lastScore = to; return; }' \
        in source


def test_the_console_uses_no_inline_svg_from_an_external_source(source):
    """The rail is drawn in-page; nothing is fetched to render it."""
    assert "<svg" in source
    assert "xlink:href" not in source
    assert "url(http" not in source


# -- Stage 12: module availability labelling ------------------------------

def test_the_page_distinguishes_disabled_from_unimplemented(source):
    """A working module that is switched off must not read as missing."""
    assert "implemented, not enabled" in source
    assert "not implemented" in source
    assert "available_modules" in source


def test_availability_comes_from_the_api_not_the_page(source):
    """Which modules exist is the API's answer, never a hardcoded list."""
    assert "mode.available_modules" in source
    assert "availableModules.includes" in source


def test_absent_modules_are_never_given_a_score(source):
    """Neither a disabled nor an unimplemented module gets a slot or a fill."""
    assert "!contributions.some" in source


# -- Stage 15: explainability ---------------------------------------------

def test_the_page_shows_the_decision_summary(source):
    """The human-readable explanation must reach the screen."""
    assert "explanation.summary" in source
    assert "class=\"summary" in source


def test_an_unavailable_module_reads_differently_from_a_zero_score(source):
    """'Could not assess' must not look like 'checked, found nothing'."""
    assert 'm.status === "ok"' in source
    assert "no score" in source
    assert ".badge.unavailable" in source


def test_the_summary_is_escaped_like_every_other_api_value(source):
    assert "esc(explanation.summary)" in source


# -- module presentation states --------------------------------------------
#
# The dashboard's problem was collapsing every module condition to a number:
# "no match", "not configured" and "not enough history yet" all rendered as
# a blank 0.00. These tests check that the six states a module's evidence
# can actually be in are each named on the page, and that none of them is a
# domain the page happens to have been tested against.

def test_the_page_names_every_module_presentation_state(source):
    for label in ["DETECTED", "NO MATCH", "NOT CONFIGURED",
                  "INSUFFICIENT OBSERVATIONS", "UNAVAILABLE"]:
        assert label in source, f"module state {label!r} is not shown"


def test_module_state_comes_from_the_api_not_a_client_side_guess(source):
    """The state must be read off `m.state`, which the API already computed
    from the module's real status and features — never re-derived from the
    score in JavaScript, which is exactly the bug being fixed."""
    assert "moduleStateBadge(m.state)" in source
    assert "MODULE_STATES" in source


def test_the_investigation_panel_shows_whether_each_module_contributed(source):
    assert "counted toward the aggregate" in source
    assert "excluded from the aggregate" in source


def test_a_domain_lookup_also_shows_per_module_signals(source):
    """'Check a domain' is how an ad hoc name gets evaluated; it must show
    the same per-module evidence as a stored decision, not just the total."""
    assert source.count("renderModuleEvidence(") >= 2


def test_the_configuration_panel_marks_enabled_modules_active(source):
    """A module the engine is actually running must read as ACTIVE, not as
    an unchecked box that looks the same as one that was never built."""
    assert "state-active" in source
    assert '"ACTIVE"' in source
    assert 'm.enabled ? "state-active" : "state-inactive"' in source


def test_the_page_contains_no_test_fixture_domains(source):
    """These two domains are illustrative examples from the bug report, not
    real detection results. Baking either into the page would fabricate a
    finding no live evaluation produced."""
    for domain in ["g00gle.com", "wappingerbicornshaps.com"]:
        assert domain not in source.lower(), \
            f"the dashboard hardcodes the example domain {domain!r}"
