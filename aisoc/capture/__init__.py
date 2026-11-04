"""Connection detection for the offline training domain (Architecture 1, stage "數據採集").

A packet source (pyshark live capture or a PCAP file) is reduced to Zeek-style
``conn.log`` rows.  Those rows are the *only* thing that leaves this package:
the same shape that Slips' Zeek writes, so ``ZeekConnIndex``, the Slips adapter
and the dashboard sensor tail consume them unchanged.

pyshark/tshark are optional: everything here is testable with ``FakePacketSource``
and the import of pyshark happens lazily inside ``PysharkSource``.
"""

from .flows import CONN_LOG_FIELDS, FlowAssembler, PacketView, conn_log_row_lines
from .pyshark_source import CaptureUnavailable, PysharkSource, packet_view_from_pyshark
from .runner import CAPTURE_MANIFEST_SCHEMA, CaptureStats, FakePacketSource, run_capture

__all__ = [
    "CAPTURE_MANIFEST_SCHEMA",
    "CONN_LOG_FIELDS",
    "CaptureStats",
    "CaptureUnavailable",
    "FakePacketSource",
    "FlowAssembler",
    "PacketView",
    "PysharkSource",
    "conn_log_row_lines",
    "packet_view_from_pyshark",
    "run_capture",
]
