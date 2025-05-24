import re
from secrets import choice
from string import ascii_letters, digits

import dns.resolver as resolver


class DomainValidator:
    """
    A class to validate domain names using generated TXT verification codes.
    """

    def __init__(self, ascii_only: bool = True, domain_max_length: int = 255):
        # Unicode domain name pattern with specific support for Hindi characters
        self.domain_re = (
            r"^((?!-)[\w\u0900-\u097F-]{1,63}(?<!-)"
            r"\.(?!-)[\w\u0900-\u097F-]{1,63}(?<!-))*$"
        )
        self.ascii_only = ascii_only  # Flag for only ASCII characters
        self.domain_max_length = domain_max_length  # Domain name maximum length

        if self.ascii_only:
            self.re_pattern = re.compile(self.domain_re, re.ASCII | re.IGNORECASE)
        else:
            self.re_pattern = re.compile(self.domain_re, re.UNICODE | re.IGNORECASE)

    def validate_domain_re(self, domain: str) -> bool:
        """
        Validate the given domain name matches the regular expression.

        Parameters:
            domain -- The domain name to validate.

        Returns:
            bool -- True if the domain name is a valid format, False otherwise.
        """
        if not domain:
            raise ValueError("Domain cannot be empty.")
        if not isinstance(domain, str):
            raise ValueError("Domain must be a string.")
        return bool(self.re_pattern.match(domain))

    def validate_domain_length(self, domain: str) -> bool:
        """
        Validate the length of the domain name.

        Parameters:
            domain -- The domain name to validate.

        Returns:
            bool -- True if the domain name length is valid, False otherwise.
        """
        if not domain:
            raise ValueError("Domain cannot be empty.")
        if not isinstance(domain, str):
            raise ValueError("Domain must be a string.")
        return len(domain) <= self.domain_max_length

    def validate_domain_dns(self, domain: str) -> bool:
        """
        Validate the domain name resolves with DNS.

        Parameters:
            domain -- The domain name to validate.

        Returns:
            bool -- True if the domain name resolves, False otherwise.
        """
        try:
            resolver.resolve(domain, "NS")
            return True
        except (resolver.NXDOMAIN, resolver.NoAnswer):
            return False

    def validate_domain(self, domain: str) -> bool:
        """
        Validate the domain name by checking format, length, and DNS resolution.

        Parameters:
            domain -- The domain name to validate.

        Returns:
            bool -- True if the domain name is valid, False otherwise.
        """
        if not self.validate_domain_re(domain):
            return False
        if not self.validate_domain_length(domain):
            return False
        if not self.validate_domain_dns(domain):
            return False
        return True

    def unicode_to_punycode(self, domain: str) -> str:
        """
        Convert a Unicode domain name to Punycode.

        Parameters:
            domain -- The Unicode domain name to convert.

        Returns:
            str -- The Punycode representation of the domain name.
        """
        if self.ascii_only is True:
            raise NotImplementedError(
                "Punycode conversion is not supported for ASCII-only mode."
            )
        if self.validate_domain_re(domain) is False:
            raise ValueError("Invalid domain name.")
        try:
            return domain.encode("idna").decode("ascii")
        except Exception as e:
            raise ValueError(f"Error converting to Punycode: {e}")

    def punycode_to_unicode(self, domain: str) -> str:
        """
        Convert a Punycode domain name to Unicode.

        Parameters:
            domain -- The Punycode domain name to convert.

        Returns:
            str -- The Unicode representation of the domain name.
        """
        if self.ascii_only is True:
            raise NotImplementedError(
                "Punycode to Unicode conversion is not supported for ASCII-only mode."
            )
        if self.validate_domain_re(domain) is False:
            raise ValueError("Invalid domain name.")
        try:
            return domain.encode("ascii").decode("idna")
        except Exception as e:
            raise ValueError(f"Error converting to Unicode: {e}")

    def generate_txt_code(self, length: int = 26, prefix: str = "") -> str:
        """
        Generate a random verification code for TXT record with optional prefix.

        Example:
            >>> generate_txt_code()
            '84yfCdasrZejOPNeFuBpgGXcvy'

        Example:
            >>> generate_txt_code(length=26, prefix="site_verify")
            'site_verify=84yfCdasrZejOPNeFuBpgGXcvy'

        Parameters:
            length -- Length of the random code to generate.
            prefix -- Optional prefix for the code (e.g., site_verify).

        Returns:
            str -- Generated string with random verification code.
        """
        if prefix and not isinstance(prefix, str):
            raise ValueError("Prefix must be a string.")
        if not isinstance(length, int) or length <= 0 or length > 255:
            raise ValueError("Length must be a positive integer and max of 255.")
        code = "".join(choice(ascii_letters + digits) for _ in range(length))
        if prefix:
            if (length + len(prefix)) > 255:
                raise ValueError(
                    "TXT record cannot exceed 255 characters, including prefix."
                )
            return f"{prefix}={code}"
        return code

    def verify_ownership(self, domain: str, txt_code: str, txt_host: str = "") -> bool:
        """
        Verify domain ownership by checking if the TXT records for the domain
        contain the provided code.

        Parameters:
            domain -- Domain being verified.
            txt_code -- Code string to verify in TXT record.
            txt_host -- Optional host (i.e., subdomain) for the TXT record.

        Returns:
            bool -- True if a TXT record contains the code, False otherwise.
        """
        if txt_host:
            domain = f"{txt_host}.{domain}"
        try:
            response = resolver.resolve(domain, "TXT")
            for rdata in response:
                if txt_code == rdata.to_text().strip('"'):
                    return True
        except (resolver.NXDOMAIN, resolver.NoAnswer) as e:
            print("Error resolving TXT records:")
            raise e
        return False
