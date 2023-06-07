"""Log reader module."""
from __future__ import annotations

import datetime
import io
import ipaddress
import os
import re
from decimal import Decimal, InvalidOperation
from gzip import GzipFile
from tempfile import NamedTemporaryFile
from types import TracebackType
from typing import IO, Optional, Union, cast
from urllib.parse import urlparse

from .exceptions import InvalidLogFileError
from .log_entry import CloudFrontLogEntry
from .types import Boto3SessionArgDict


class _CloudFrontLogIterator:
    """CloudFront log iterator."""

    def __init__(self: _CloudFrontLogIterator, fp: IO[bytes]) -> None:
        """Initialize iterator.

        Args:
            fp(IO): Input stream
        """
        magic_check = fp.read(2)
        fp.seek(0, io.SEEK_SET)
        if magic_check == b"\x1f\x8b":
            self._fp = cast(IO[bytes], GzipFile(mode="rb", fileobj=fp))
        else:
            self._fp = fp
        self._wrapper = io.TextIOWrapper(self._fp, "utf-8")
        vline = self._wrapper.readline().strip()
        if not re.match(r"^#\s*Version:\s*1\.0$", vline):
            raise InvalidLogFileError("Log file version line is invalid")
        fline = self._wrapper.readline().strip()
        fl_md = re.match(r"^#\s*Fields:\s*(.+)$", fline)
        if not fl_md:
            raise InvalidLogFileError("Log file fields line is invalid")
        fields_list_s: str = fl_md[1]
        self._fields: list[str] = re.split(r"\s+", fields_list_s)

    def __iter__(self: _CloudFrontLogIterator) -> _CloudFrontLogIterator:
        """Return iterator.

        Returns:
            _CloudFrontLogIterator: self
        """
        return self

    def __next__(self: _CloudFrontLogIterator) -> CloudFrontLogEntry:
        """Return next item.

        Returns:
            CloudFrontLogEntry: log entry

        Raises:
            StopIteration: If no more entries found.
        """
        line = self._wrapper.readline()
        if line == "":
            raise StopIteration("The file is end of file.")
        while line.startswith("#"):
            line = self._wrapper.readline()
            if line == "":
                raise StopIteration("The file is end of file.")
        fields_values = line.strip().split("\t")
        fields_data: dict[str, Optional[str]] = {}
        for i, field_name in enumerate(self._fields):
            if len(fields_values) <= i + 1:
                fields_data[field_name] = None
            else:
                field_value = fields_values[i]
                if field_value == "-":
                    fields_data[field_name] = None
                else:
                    fields_data[field_name] = field_value
        if "date" not in fields_data or "time" not in fields_data:
            raise InvalidLogFileError("Date or time fields not found")
        if fields_data["date"] is None or fields_data["time"] is None:
            raise InvalidLogFileError("Date or time field is empty")
        dt = datetime.date.fromisoformat(fields_data["date"])
        tm = datetime.time.fromisoformat(fields_data["time"])
        log_time = datetime.datetime.combine(
            dt, tm, tzinfo=datetime.timezone.utc
        )
        edge_location = fields_data.get("x-edge-location")
        if edge_location is None:
            raise InvalidLogFileError("Edge location is not set")
        sent_bytes_s = fields_data.get("sc-bytes")
        if sent_bytes_s is None:
            raise InvalidLogFileError("Sent bytes size is not set")
        try:
            sent_bytes = int(sent_bytes_s)
        except ValueError as e:
            raise InvalidLogFileError("Sent bytes size is not number") from e
        client_ip_addr_s = fields_data.get("c-ip")
        if client_ip_addr_s is None:
            raise InvalidLogFileError("Client IP address is not set")
        try:
            client_ip_addr = ipaddress.ip_address(client_ip_addr_s)
        except ValueError:
            raise InvalidLogFileError("Invalid client IP address")
        request_method = fields_data.get("cs-method")
        if request_method is None:
            raise InvalidLogFileError("Request method is not set")
        distribution_host = fields_data.get("cs(Host)")
        if distribution_host is None:
            raise InvalidLogFileError("Distribution host is not set")
        request_uri_stem = fields_data.get("cs-uri-stem")
        if request_uri_stem is None:
            raise InvalidLogFileError("Request URI stem is not set")
        sc_s_s = fields_data.get("sc-status")
        if sc_s_s is None:
            status_code = 0
        elif sc_s_s == "000":
            status_code = 0
        elif re.match(r"^[1-5][0-9][0-9]$", sc_s_s):
            status_code = int(sc_s_s)
        else:
            raise InvalidLogFileError("Status code is invalid")
        referer = fields_data.get("cs(Referer)")
        if referer == "-":
            referer = None
        user_agent = fields_data.get("cs(User-Agent)")
        if user_agent == "-":
            user_agent = None
        query_string = fields_data.get("cs-uri-query")
        if query_string == "-":
            query_string = None
        cookie = fields_data.get("cs(Cookie)")
        if cookie == "-":
            cookie = None
        edge_result_type = fields_data.get("x-edge-result-type")
        if edge_result_type is None:
            raise InvalidLogFileError("Edge result type is not set")
        request_id = fields_data.get("x-edge-request-id")
        if request_id is None:
            raise InvalidLogFileError("Request ID is not set")
        request_host = fields_data.get("x-host-header")
        if request_host is None:
            raise InvalidLogFileError("Request host is not set")
        request_protocol = fields_data.get("cs-protocol")
        if request_protocol is None:
            raise InvalidLogFileError("Request protocol is not set")
        received_bytes_s = fields_data.get("cs-bytes")
        if received_bytes_s is None:
            raise InvalidLogFileError("Received bytes size is not set")
        try:
            received_bytes = int(received_bytes_s)
        except ValueError as e:
            raise InvalidLogFileError("Invalid received bytes size") from e
        time_taken_s = fields_data.get("time-taken")
        if time_taken_s is None:
            raise InvalidLogFileError("Taken time is not set")
        try:
            time_taken = Decimal(time_taken_s)
        except InvalidOperation as e:
            raise InvalidLogFileError("Invalid time taken") from e
        forwarded_for_s = fields_data.get("x-forwarded-for")
        if forwarded_for_s is None or forwarded_for_s == "-":
            forwarded_for: Union[
                ipaddress.IPv4Address,
                ipaddress.IPv6Address,
                None,
            ] = None
        else:
            try:
                forwarded_for = ipaddress.ip_address(forwarded_for_s)
            except ValueError:
                forwarded_for = None
        tls_proto = fields_data.get("ssl-protocol")
        if request_protocol == "http" or tls_proto == "-":
            tls_proto = None
        tls_cipher = fields_data.get("ssl-cipher")
        if request_protocol == "http" or tls_cipher == "-":
            tls_cipher = None
        edge_response_result_type = fields_data.get(
            "x-edge-response-result-type"
        )
        if edge_response_result_type is None:
            raise InvalidLogFileError("Edge response result type is not set")
        http_proto = fields_data.get("cs-protocol-version")
        if http_proto is None:
            raise InvalidLogFileError("Protocol version is not set")
        fle_status = fields_data.get("fle-status")
        if fle_status == "-":
            fle_status = None
        fle_encrypted_fields_s = fields_data.get("fle-encrypted-fields")
        if fle_encrypted_fields_s is None or fle_encrypted_fields_s == "-":
            fle_encrypted_fields: Optional[int] = None
        else:
            try:
                fle_encrypted_fields = int(fle_encrypted_fields_s)
            except ValueError:
                fle_encrypted_fields = None
        client_port_s = fields_data.get("c-port")
        if client_port_s is None:
            raise InvalidLogFileError("Client port is not set")
        try:
            client_port = int(client_port_s)
        except ValueError as e:
            raise InvalidLogFileError("Invalid client port") from e
        time_to_first_bytes_s = fields_data.get("time-to-first-byte")
        if time_to_first_bytes_s is None:
            raise InvalidLogFileError("Time to first bytes is not set")
        try:
            time_to_first_bytes = Decimal(time_to_first_bytes_s)
        except InvalidOperation as e:
            raise InvalidLogFileError("Invalid time to first bytes") from e
        edge_detailed_result_type = fields_data.get(
            "x-edge-detailed-result-type"
        )
        if edge_detailed_result_type is None:
            edge_detailed_result_type = edge_result_type
        content_type = fields_data.get("sc-content-type")
        if content_type == "-":
            content_type = None
        content_length_s = fields_data.get("sc-content-len")
        if content_length_s is None or content_length_s == "-":
            content_length: Optional[int] = None
        else:
            try:
                content_length = int(content_length_s)
            except ValueError:
                content_length = None
        range_start_s = fields_data.get("sc-range-start")
        if range_start_s is None or range_start_s == "-":
            range_start: Optional[int] = None
        else:
            try:
                range_start = int(range_start_s)
            except ValueError:
                range_start = None
        range_end_s = fields_data.get("sc-range-end")
        if range_end_s is None or range_end_s == "-":
            range_end: Optional[int] = None
        else:
            try:
                range_end = int(range_end_s)
            except ValueError:
                range_end = None
        return CloudFrontLogEntry(
            log_time,
            edge_location,
            sent_bytes,
            client_ip_addr,
            request_method,
            distribution_host,
            request_uri_stem,
            status_code,
            referer,
            user_agent,
            query_string,
            cookie,
            edge_result_type,
            request_id,
            request_host,
            request_protocol,
            received_bytes,
            time_taken,
            forwarded_for,
            tls_proto,
            tls_cipher,
            edge_response_result_type,
            http_proto,
            fle_status,
            fle_encrypted_fields,
            client_port,
            time_to_first_bytes,
            edge_detailed_result_type,
            content_type,
            content_length,
            range_start,
            range_end,
        )


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
        self._fp: Optional[IO[bytes]] = None
        if self._source.startswith("s3://"):
            uri = urlparse(self._source)
            if uri.scheme != "s3":
                raise ValueError("Invalid source")
            if uri.path == "":
                raise ValueError("Invalid source")

    def __enter__(self: CloudFrontLogReader) -> _CloudFrontLogIterator:
        """Initialize context.

        Returns:
            Log entry iterator
        """
        if self._source.startswith("s3://"):
            uri = urlparse(self._source)
            suffix = os.path.splitext(uri.path)[1]
            self._fp = NamedTemporaryFile(suffix=suffix)
            from boto3.session import Session

            sess = Session(**self._boto3_args)
            s3 = sess.resource("s3")
            bucket = s3.Bucket(uri.netloc)
            obj = bucket.Object(uri.path[1:])
            obj.download_fileobj(self._fp)
            self._fp.seek(0, io.SEEK_SET)
        else:
            self._fp = open(self._source, "rb")
        return _CloudFrontLogIterator(self._fp)

    def __exit__(
        self: CloudFrontLogReader,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Optional[bool]:
        """."""
        if self._fp:
            self._fp.close()
        return None
