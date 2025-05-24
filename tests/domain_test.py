from contextlib import nullcontext

import dns.resolver as resolver
import pytest

from domain_validator import DomainValidator

domain_validator = DomainValidator()
unicode_domain_validator = DomainValidator(ascii_only=False)
short_domain_validator = DomainValidator(domain_max_length=150)


@pytest.mark.parametrize(
    "domain, expected",
    [
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
    ],
)
def test_unicode_domain_re(domain, expected):
    """
    Test the Unicode domain name validation using regular expression.
    """
    with expected as e:
        assert unicode_domain_validator.validate_domain_re(domain) == e


@pytest.mark.parametrize(
    "domain, expected",
    [
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
    ],
)
def test_ascii_domain_re(domain, expected):
    """
    Test the ASCII domain name validation using regular expression.
    """
    with expected as e:
        assert domain_validator.validate_domain_re(domain) == e


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("too-long-name." * 20 + "com", nullcontext(False)),
        ("too-long-name." * 18 + "com", nullcontext(True)),
        ("000000.org", nullcontext(True)),
        ("domain.with.idn.tld.उदाहरण.परीक्षकЂҁ", nullcontext(True)),
        (None, pytest.raises(ValueError)),
        ("", pytest.raises(ValueError)),
        (123, pytest.raises(ValueError)),
    ],
)
def test_default_domain_length(domain, expected):
    """
    Test the domain name length validation.
    """
    with expected as e:
        assert domain_validator.validate_domain_length(domain) == e


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("too-long-name." * 18 + "com", nullcontext(False)),
        ("too-long-name." * 10 + "com", nullcontext(True)),
        ("000000.org", nullcontext(True)),
        ("domain.with.idn.tld.उदाहरण.परीक्षकЂҁ", nullcontext(True)),
        (None, pytest.raises(ValueError)),
        ("", pytest.raises(ValueError)),
        (123, pytest.raises(ValueError)),
    ],
)
def test_custom_domain_length(domain, expected):
    """
    Test the custom domain name length validation.
    """
    with expected as e:
        assert short_domain_validator.validate_domain_length(domain) == e


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("google.com", True),
        ("facebook.com", True),
        ("dashinpunytld.xn---c", False),
        ("xn--7ca6byfyc.com", False),
        ("we24.com", True),
        ("DJANGOPROJECT.COM", True),
    ],
)
def test_domain_dns(domain, expected):
    """
    Test the domain name DNS validation.
    """
    assert domain_validator.validate_domain_dns(domain) == expected


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("python.org", True),
        ("python-.org", False),
        ("too-long-name." * 20 + "com", False),
        ("xn--7ca6byfyc.com", False),
    ],
)
def test_domain_name(domain, expected):
    """
    Test all domain name validation steps using the validate_name function.
    """
    assert domain_validator.validate_domain(domain) == expected


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("google.com", nullcontext("google.com")),
        ("facebook.com", nullcontext("facebook.com")),
        ("例子.测试", nullcontext("xn--fsqu00a.xn--0zwm56d")),
        ("python-.org", pytest.raises(ValueError)),
        ("1:2:3:4:5:6:7:8", pytest.raises(ValueError)),
        ("stupid-name试", pytest.raises(ValueError)),
        (None, pytest.raises(ValueError)),
        ("", pytest.raises(ValueError)),
        (123, pytest.raises(ValueError)),
        ("例子测试" * 15 + ".com", pytest.raises(ValueError)),
    ],
)
def test_unicode_to_punycode(domain, expected):
    """
    Test the conversion of Unicode domain names to Punycode.
    """
    with expected as e:
        assert unicode_domain_validator.unicode_to_punycode(domain) == e


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("google.com", pytest.raises(NotImplementedError)),
        ("facebook.com", pytest.raises(NotImplementedError)),
        ("例子.测试", pytest.raises(NotImplementedError)),
        ("python-.org", pytest.raises(NotImplementedError)),
        ("1:2:3:4:5:6:7:8", pytest.raises(NotImplementedError)),
        ("stupid-name试", pytest.raises(NotImplementedError)),
        (None, pytest.raises(NotImplementedError)),
        ("", pytest.raises(NotImplementedError)),
        (123, pytest.raises(NotImplementedError)),
        ("例子测试" * 15 + ".com", pytest.raises(NotImplementedError)),
    ],
)
def test_unicode_to_punycode_ascii_enabled(domain, expected):
    """
    Test the conversion of Unicode domain names to Punycode in ASCII-only mode.
    """
    with expected as e:
        assert domain_validator.unicode_to_punycode(domain) == e


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("google.com", nullcontext("google.com")),
        ("facebook.com", nullcontext("facebook.com")),
        ("xn--fsqu00a.xn--0zwm56d", nullcontext("例子.测试")),
        ("python-.org", pytest.raises(ValueError)),
        ("1:2:3:4:5:6:7:8", pytest.raises(ValueError)),
        ("stupid-name试", pytest.raises(ValueError)),
        (None, pytest.raises(ValueError)),
        ("", pytest.raises(ValueError)),
        (123, pytest.raises(ValueError)),
        ("例子测试.com", pytest.raises(ValueError)),
    ],
)
def test_punycode_to_unicode(domain, expected):
    """
    Test the conversion of Punycode domain names to Unicode.
    """
    with expected as e:
        assert unicode_domain_validator.punycode_to_unicode(domain) == e


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("google.com", pytest.raises(NotImplementedError)),
        ("facebook.com", pytest.raises(NotImplementedError)),
        ("xn--fsqu00a.xn--0zwm56d", pytest.raises(NotImplementedError)),
        ("python-.org", pytest.raises(NotImplementedError)),
        ("1:2:3:4:5:6:7:8", pytest.raises(NotImplementedError)),
        ("stupid-name试", pytest.raises(NotImplementedError)),
        (None, pytest.raises(NotImplementedError)),
        ("", pytest.raises(NotImplementedError)),
        (123, pytest.raises(NotImplementedError)),
        ("例子测试.com", pytest.raises(NotImplementedError)),
    ],
)
def test_punycode_to_unicode_ascii_enabled(domain, expected):
    """
    Test the conversion of Punycode domain names to Unicode in ASCII-only mode.
    """
    with expected as e:
        assert domain_validator.punycode_to_unicode(domain) == e


@pytest.mark.parametrize(
    "length, expected",
    [
        (-1, pytest.raises(ValueError)),
        (0, pytest.raises(ValueError)),
        ("", pytest.raises(ValueError)),
        (256, pytest.raises(ValueError)),
        (26, nullcontext(str)),
    ],
)
def test_generate_txt_code(length, expected):
    """
    Test the generation of TXT codes.
    """
    with expected as e:
        assert type(domain_validator.generate_txt_code(length)) == e


@pytest.mark.parametrize(
    "prefix, length, expected",
    [
        ("", 26, nullcontext(str)),
        (b"test-domain", 26, pytest.raises(ValueError)),
        ("test-domain", 0, pytest.raises(ValueError)),
        ("test-domain", 256, pytest.raises(ValueError)),
        ("test-domain", 250, pytest.raises(ValueError)),
        ("test-domain", 30, nullcontext(str)),
    ],
)
def test_generate_prefixed_txt_code(prefix, length, expected):
    """
    Test the generation of TXT codes with a prefix.
    """
    with expected as e:
        assert type(domain_validator.generate_txt_code(length, prefix)) == e


@pytest.mark.parametrize(
    "domain, txt_code, txt_host, expected",
    [
        (
            "stacynoland.com",
            "test-domain=84yfCdasrZejOPNeFuBpgGXcvy",
            None,
            nullcontext(True),
        ),
        (
            "stacynoland.com",
            "84yfCdasrZejOPNeFuBpgGXcvy",
            "test-domain",
            nullcontext(True),
        ),
        ("stacynoland.com", "NotAValidCode", None, nullcontext(False)),
        ("stacynoland.com", "NotAValidCode", "test-domain", nullcontext(False)),
        (
            "notvalidstacynoland.com",
            "84yfCdasrZejOPNeFuBpgGXcvy",
            None,
            pytest.raises(resolver.NXDOMAIN),
        ),
    ],
)
def test_verify_ownership(domain, txt_code, txt_host, expected):
    """
    Test the verification of TXT codes.
    """
    with expected as e:
        assert domain_validator.verify_ownership(domain, txt_code, txt_host) == e
