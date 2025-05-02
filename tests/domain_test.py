from contextlib import nullcontext

import pytest

from domain_validator import DomainValidator, domain_validator


ascii_domain_validator = DomainValidator(ascii_only=True)
short_domain_validator = DomainValidator(domain_max_length=150)


@pytest.mark.parametrize("domain, expected", [
    ("000000.org", nullcontext(True)),
    ("python.org", nullcontext(True)),
    ("python.co.uk", nullcontext(True)),
    ("python.tk", nullcontext(True)),
    ("hg.python.org", nullcontext(True)),
    ("python-python.com", nullcontext(True)),
    ("domain.with.idn.tld.उदाहरण.परीक्षकЂҁ", nullcontext(True)),
    ("例子.测试", nullcontext(True)),
    ("ıçğü.com", nullcontext(True)),
    ("python.name.uk", nullcontext(True)),
    ("dashinpunytld.xn---c", nullcontext(True)),
    ("xn--7ca6byfyc.com", nullcontext(True)),
    ("we24.com", nullcontext(True)),
    ("DJANGOPROJECT.COM", nullcontext(True)),
    ("255.0.0.0", nullcontext(False)),
    ("fe80::1", nullcontext(False)),
    ("python..org", nullcontext(False)),
    ("python-.org", nullcontext(False)),
    ("1:2:3:4:5:6:7:8", nullcontext(False)),
    ("stupid-name试", nullcontext(False)),
    (None, pytest.raises(ValueError)),
    ("", pytest.raises(ValueError)),
    (123, pytest.raises(ValueError)),
])
def test_domain_re(domain, expected):
    """
    Test the domain name validation using regular expression.
    """
    with expected as e:
        assert domain_validator.validate_domain_re(domain) == e


@pytest.mark.parametrize("domain, expected", [
    ("000000.org", nullcontext(True)),
    ("python.org", nullcontext(True)),
    ("python.co.uk", nullcontext(True)),
    ("python.tk", nullcontext(True)),
    ("hg.python.org", nullcontext(True)),
    ("python-python.com", nullcontext(True)),
    ("domain.with.idn.tld.उदाहरण.परीक्षकЂҁ", nullcontext(False)),
    ("例子.测试", nullcontext(False)),
    ("ıçğü.com", nullcontext(False)),
    ("python.name.uk", nullcontext(True)),
    ("dashinpunytld.xn---c", nullcontext(True)),
    ("xn--7ca6byfyc.com", nullcontext(True)),
    ("we24.com", nullcontext(True)),
    ("DJANGOPROJECT.COM", nullcontext(True)),
    ("255.0.0.0", nullcontext(False)),
    ("fe80::1", nullcontext(False)),
    ("python..org", nullcontext(False)),
    ("python-.org", nullcontext(False)),
    ("1:2:3:4:5:6:7:8", nullcontext(False)),
    ("stupid-name试", nullcontext(False)),
    (None, pytest.raises(ValueError)),
    ("", pytest.raises(ValueError)),
    (123, pytest.raises(ValueError)),
])
def test_ascii_domain_re(domain, expected):
    """
    Test the ASCII domain name validation using regular expression.
    """
    with expected as e:
        assert ascii_domain_validator.validate_domain_re(domain) == e


@pytest.mark.parametrize("domain, expected", [
    ("too-long-name." * 20 + "com", nullcontext(False)),
    ("too-long-name." * 18 + "com", nullcontext(True)),
    ("000000.org", nullcontext(True)),
    ("domain.with.idn.tld.उदाहरण.परीक्षकЂҁ", nullcontext(True)),
    (None, pytest.raises(ValueError)),
    ("", pytest.raises(ValueError)),
    (123, pytest.raises(ValueError)),
])
def test_default_domain_length(domain, expected):
    """
    Test the domain name length validation.
    """
    with expected as e:
        assert domain_validator.validate_domain_length(domain) == e


@pytest.mark.parametrize("domain, expected", [
    ("too-long-name." * 18 + "com", nullcontext(False)),
    ("too-long-name." * 10 + "com", nullcontext(True)),
    ("000000.org", nullcontext(True)),
    ("domain.with.idn.tld.उदाहरण.परीक्षकЂҁ", nullcontext(True)),
    (None, pytest.raises(ValueError)),
    ("", pytest.raises(ValueError)),
    (123, pytest.raises(ValueError)),
])
def test_custom_domain_length(domain, expected):
    """
    Test the custom domain name length validation.
    """
    with expected as e:
        assert short_domain_validator.validate_domain_length(domain) == e


@pytest.mark.parametrize("domain, expected", [
    ("google.com", True),
    ("facebook.com", True),
    ("dashinpunytld.xn---c", False),
    ("xn--7ca6byfyc.com", False),
    ("we24.com", True),
    ("DJANGOPROJECT.COM", True),
])
def test_domain_dns(domain, expected):
    """
    Test the domain name DNS validation.
    """
    assert domain_validator.validate_domain_dns(domain) == expected


@pytest.mark.parametrize("domain, expected", [
    ("python.org", True),
    ("python-.org", False),
    ("too-long-name." * 20 + "com", False),
    ("xn--7ca6byfyc.com", False),
])
def test_domain_name(domain, expected):
    """
    Test all domain name validation steps using the validate_domain_name function.
    """
    assert domain_validator.validate_domain_name(domain) == expected


@pytest.mark.parametrize("domain, expected", [
    ("google.com", "google.com"),
    ("facebook.com", "facebook.com"),
    ("例子.测试", "xn--fsqu00a.xn--0zwm56d"),
])
def test_unicode_to_punycode(domain, expected):
    """
    Test the conversion of Unicode domain names to Punycode.
    """
    assert domain_validator.unicode_to_punycode(domain) == expected


@pytest.mark.parametrize("domain, expected", [])
def test_punycode_to_unicode(domain, expected):
    """
    Test the conversion of Punycode domain names to Unicode.
    """
    assert domain_validator.punycode_to_unicode(domain) == expected
