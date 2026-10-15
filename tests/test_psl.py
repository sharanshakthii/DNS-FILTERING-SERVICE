"""Public Suffix List helper.

Most expectations are taken from the PSL project's own test vectors
(https://github.com/publicsuffix/list/blob/main/tests/test_psl.txt); the rest
pin the platform cases this project depends on.
"""

import pytest

from feeds import psl


@pytest.mark.parametrize("name,expected", [
    # Official vectors (ICANN behaviour).
    ("com", None),
    ("example.com", "example.com"),
    ("b.example.com", "example.com"),
    ("a.b.example.com", "example.com"),
    ("uk.com", None),
    ("example.uk.com", "example.uk.com"),
    ("b.example.uk.com", "example.uk.com"),
    ("biz", None),
    ("domain.biz", "domain.biz"),
    ("jp", None),
    ("test.jp", "test.jp"),
    ("www.test.jp", "test.jp"),
    ("ac.jp", None),
    ("test.ac.jp", "test.ac.jp"),
    ("kyoto.jp", None),
    ("test.kyoto.jp", "test.kyoto.jp"),
    ("ide.kyoto.jp", None),
    ("b.ide.kyoto.jp", "b.ide.kyoto.jp"),
    # Wildcard and exception rules.
    ("c.kobe.jp", None),
    ("b.c.kobe.jp", "b.c.kobe.jp"),
    ("city.kobe.jp", "city.kobe.jp"),
    ("www.city.kobe.jp", "city.kobe.jp"),
    ("ck", None),
    ("test.ck", None),
    ("b.test.ck", "b.test.ck"),
    ("www.ck", "www.ck"),
    ("www.www.ck", "www.ck"),
    # Unlisted TLD: the implicit "*" rule.
    ("example.example", "example.example"),
    ("b.example.example", "example.example"),
    # Trailing dot and case are normalised.
    ("WWW.Example.COM.", "example.com"),
])
def test_official_vectors(name, expected):
    assert psl.registrable_domain(name) == expected


def test_multi_label_suffixes_the_old_approximation_got_wrong():
    assert psl.registrable_domain("paypal-login.co.uk") == "paypal-login.co.uk"
    assert psl.registrable_label("paypal-login.co.uk") == "paypal-login"
    assert psl.registrable_domain("www.local.gov.uk") == "local.gov.uk"


@pytest.mark.parametrize("name,site,registration", [
    ("okns29-hbk14.vercel.app", "okns29-hbk14.vercel.app", "vercel.app"),
    ("x.y.pages.dev", "y.pages.dev", "pages.dev"),
    ("www.shopee3125.blogspot.com", "shopee3125.blogspot.com", "blogspot.com"),
])
def test_private_platforms_have_a_site_and_a_registration(name, site, registration):
    assert psl.registrable_domain(name, private=True) == site
    assert psl.registrable_domain(name, private=False) == registration
    assert psl.on_shared_platform(name)


def test_an_ordinary_domain_is_not_a_shared_platform():
    assert not psl.on_shared_platform("mail.google.com")
    assert psl.registrable_label("mail.google.com") == "google"


def test_punycode_names_match_unicode_rules():
    # "公司.cn" is listed in Unicode; DNS carries it as punycode.
    suffix = "公司.cn".encode("idna").decode()
    assert psl.registrable_domain(f"example.{suffix}") == f"example.{suffix}"


def test_the_pinned_list_identifies_its_version():
    assert psl.version() and psl.version().startswith("20")


def test_empty_and_garbage_names_do_not_raise():
    assert psl.registrable_domain("") is None
    assert psl.registrable_domain("...") is None
    assert psl.registrable_label("") == ""
