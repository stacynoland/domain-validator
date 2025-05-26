![Domain Validator Logo](https://github.com/user-attachments/assets/4f304fee-2cee-4560-9c6f-df0c747603fd)
[![Tests](https://github.com/stacynoland/domain-validator/actions/workflows/tests.yml/badge.svg)](https://github.com/stacynoland/domain-validator/actions/workflows/tests.yml)
![Coverage](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fstacynoland.com%2Fdomain-validator%2Fcoverage.json&query=%24.totals.percent_covered_display&suffix=%25&label=coverage&color=3fb831)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/domain-validator?logo=python&logoColor=yellow)
![PyPI - Version](https://img.shields.io/pypi/v/domain-validator)
![PyPI - Status](https://img.shields.io/pypi/status/domain-validator?label=status)
[![Black](https://img.shields.io/badge/code%20style-black-000000)](https://github.com/psf/black)


# domain-validator

A Python package for validating domain names, checking their DNS resolution, and converting between Unicode and Punycode formats. The package also provides a method to generate a random code for TXT records which can be added to a domain's DNS for verifying ownership.

## Installation

To install the package, you can use pip or a dependency manager like Poetry:

`pip install domain-validator`

or

`poetry add domain-validator`

## Usage

```python
from domain_validator import DomainValidator

# Create a DomainValidator instance
validator = DomainValidator()

# Verify domain matches valid pattern
validator.validate_domain_re("example.com")

# Max domain length check
validator.validate_domain_length("example.com")

# Verify domain is not a reserved domain and dns resolves
validator.validate_domain_dns("example.com")

# Check regex pattern, length, and dns resolution
validator.validate_domain("example.com")

# Convert domain to punycode - Only available if unicode is enabled
validator.unicode_to_punycode("例子.测试")

# Convert punycode to unicode - Only available if unicode is enabled
validator.punycode_to_unicode("xn--fsqu00a.xn--0zwm56d")

# Generate a random code for TXT record verification
validator.generate_txt_code("example.com", prefix="myservice")

# Verify the TXT record was added to the domain's DNS
validator.verify_ownership("example.com", "myservice=84yfCdasrZejOPNeFuBpgGXcvy")
```
