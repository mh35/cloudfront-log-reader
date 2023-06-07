"""Log entry module."""
from __future__ import annotations

import datetime
from dataclasses import dataclass
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union


@dataclass
class CloudFrontLogEntry:
    """Amazon CloudFront log line entry."""

    log_time: datetime.datetime
    edge_location: str
    sent_bytes: int
    client_ip_addr: Union[IPv4Address, IPv6Address]
    request_method: str
    distribution_host: str
    request_uri_stem: str
    status_code: int
    referer: Optional[str]
    user_agent: Optional[str]
    query_string: Optional[str]
    cookie: Optional[str]
    edge_result_type: str
    request_id: str
    request_host: str
    request_protocol: str
    received_bytes: int
    time_taken: Decimal
    forwarded_for: Union[IPv4Address, IPv6Address, None]
    tls_proto: Optional[str]
    tls_cipher: Optional[str]
    edge_response_result_type: str
    http_proto: str
    fle_status: Optional[str]
    fle_encrypted_fields: Optional[int]
    client_port: int
    time_to_first_bytes: Decimal
    edge_detailed_result_type: str
    content_type: Optional[str]
    content_length: Optional[int]
    range_start: Optional[int]
    range_end: Optional[int]
