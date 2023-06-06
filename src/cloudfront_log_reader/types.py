"""Type definitions."""
from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from botocore.session import Session


class Boto3SessionArgDict(TypedDict, total=False):
    """Boto3 session argument dictionary."""

    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: str
    region_name: str
    botocore_session: "Session"
    profile_name: str
