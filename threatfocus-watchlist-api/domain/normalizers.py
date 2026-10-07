import ipaddress
import re
from urllib.parse import urlparse
from core.exceptions import InvalidIndicatorException
from domain.models import IndicatorType, MatchType

# Matrix Configuration mapping allowed match types
ALLOWED_MATCH_TYPES = {
    IndicatorType.EMAIL: {MatchType.EXACT},
    IndicatorType.DOMAIN: {MatchType.EXACT, MatchType.SUFFIX},
    IndicatorType.IPV4: {MatchType.EXACT},
    IndicatorType.IPV6: {MatchType.EXACT},
    IndicatorType.MD5: {MatchType.EXACT},
    IndicatorType.SHA1: {MatchType.EXACT},
    IndicatorType.SHA256: {MatchType.EXACT},
    IndicatorType.KEYWORD: {MatchType.EXACT, MatchType.CONTAINS, MatchType.PREFIX, MatchType.SUFFIX},
}

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
HEX_REGEX = re.compile(r"^[a-fA-F0-9]+$")
FQDN_REGEX = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


class IndicatorNormalizer:
    @staticmethod
    def validate_and_normalize(
        indicator_type: IndicatorType, match_type: MatchType, raw_value: str
    ) -> str:
        # Step 1: Validate Indicator Type / Match Type Matrix
        if match_type not in ALLOWED_MATCH_TYPES[indicator_type]:
            raise InvalidIndicatorException(
                message=f"Match type '{match_type.value}' is not allowed for indicator type '{indicator_type.value}'.",
                code="INVALID_MATCH_TYPE",
            )

        value = raw_value.strip()
        if not value:
            raise InvalidIndicatorException("Indicator value cannot be empty.")

        # Step 2: Apply specific normalization rules per Indicator Type
        if indicator_type == IndicatorType.EMAIL:
            lowered = value.lower()
            if not EMAIL_REGEX.match(lowered):
                raise InvalidIndicatorException(f"Invalid EMAIL format: '{value}'.")
            return lowered

        elif indicator_type == IndicatorType.DOMAIN:
            # Strip protocol if provided (e.g. http:// or https://) or trailing slashes/paths
            if "://" in value:
                parsed = urlparse(value)
                cleaned = parsed.netloc or parsed.path
            else:
                cleaned = value.split("/")[0]

            # Remove port if present
            cleaned = cleaned.split(":")[0].lower().rstrip(".")

            if not FQDN_REGEX.match(cleaned):
                raise InvalidIndicatorException(f"Invalid DOMAIN format: '{value}'.")
            return cleaned

        elif indicator_type == IndicatorType.IPV4:
            try:
                ip = ipaddress.IPv4Address(value)
                return str(ip)
            except ValueError:
                raise InvalidIndicatorException(f"Invalid IPV4 address: '{value}'.")

        elif indicator_type == IndicatorType.IPV6:
            try:
                ip = ipaddress.IPv6Address(value)
                return ip.compressed
            except ValueError:
                raise InvalidIndicatorException(f"Invalid IPV6 address: '{value}'.")

        elif indicator_type in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}:
            expected_lens = {
                IndicatorType.MD5: 32,
                IndicatorType.SHA1: 40,
                IndicatorType.SHA256: 64,
            }
            target_len = expected_lens[indicator_type]
            if len(value) != target_len or not HEX_REGEX.match(value):
                raise InvalidIndicatorException(
                    f"Invalid {indicator_type.value} hash. Must be {target_len} hex characters."
                )
            return value.lower()

        elif indicator_type == IndicatorType.KEYWORD:
            if not (1 <= len(value) <= 255):
                raise InvalidIndicatorException(
                    "KEYWORD indicator length must be between 1 and 255 characters."
                )
            # Preserve original casing, return trimmed whitespace
            return value

        raise InvalidIndicatorException(f"Unsupported indicator type: {indicator_type}")