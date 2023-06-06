"""Log reader module."""
from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from .types import Boto3SessionArgDict


class CloudFrontLogReader:
    """Amazon CloudFront log reader class."""

    def __init__(
        self: CloudFrontLogReader,
        source: str,
        *,
        boto3_args: Boto3SessionArgDict = {},
    ) -> None:
        """Initialize reader.

        Args:
            source(str): Source target
            boto3_args(dict): boto3 session argument
        """
        self._source = source
        self._boto3_args = boto3_args
        self._content: Optional[bytes] = None
        if self._source.startswith("s3://"):
            uri = urlparse(self._source)
            if uri.scheme != "s3":
                raise ValueError("Invalid source")
            if uri.path == "":
                raise ValueError("Invalid source")
