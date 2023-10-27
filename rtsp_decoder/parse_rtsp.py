from os.path import basename
from enum import Enum
from urllib.parse import urlparse

from pyshark import FileCapture
import sdp_transform

from typing import NamedTuple, Dict, Tuple

import logging


class RTSPTransportHeader(NamedTuple):
    protocol: str
    options: Dict[str, str]

    @classmethod
    def parse(cls, header_str: str) -> "RTSPTransportHeader":
        transport_header_values = header_str.split(";")
        protocol = transport_header_values[0]
        options = dict()
        for option in transport_header_values[1:]:
            key, value = option.split("=", 1) if "=" in option else (option, None)
            options[key] = value

        return cls(protocol=protocol, options=options)


class RTSPTrack(NamedTuple):
    server_ip: str
    server_port: int
    client_port: int

    def get_display_filter(self) -> str:
        display_filter = f"ip.src == {self.server_ip} and "
        display_filter += f"udp.srcport == {self.server_port} and "
        display_filter += f"udp.dstport == {self.client_port}"
        return display_filter


class RTSPDataExtractor:
    """
    Find the first RTSP stream, and extract from it the stream name, the sdp and the tracks
    """

    def __init__(self, pcap_path: str):
        self.logger = logging.getLogger(__name__)
        self.stream_name = None
        self.sdp = None
        self.tracks: Dict[str, RTSPTrack] = dict()

        # Currently only taking the first stream we find
        with FileCapture(pcap_path, display_filter=f"rtsp") as cap:
            try:
                first_rtsp = cap.next()
            except StopIteration:
                raise ValueError("Could not find RTSP stream")

        self.logger.debug(
            f"Found RTSP stream: {first_rtsp.ip.src}:{first_rtsp.tcp.srcport}"
            + f" <--> {first_rtsp.ip.dst}:{first_rtsp.tcp.dstport}"
        )
        tcp_stream = first_rtsp.tcp.stream

        # We disable sdp so we can access the SDP data directly
        with FileCapture(
            pcap_path,
            display_filter=f"rtsp and tcp.stream == {tcp_stream}",
            disable_protocol="sdp",
        ) as cap:
            self.stream_name, self.sdp, self.tracks = self._extract_rtsp_data(cap)

    def _extract_rtsp_data(
        self, capture: FileCapture
    ) -> Tuple[str, dict, Dict[str, RTSPTrack]]:
        stream_name = None
        sdp = None
        tracks: Dict[str, RTSPTrack] = dict()
        try:
            stream_url, sdp = self._get_sdp(capture)
            stream_name = basename(urlparse(stream_url).path)
            self.logger.debug(f"Found SDP, stream url is {stream_url}")

            while True:
                track_id, track = self._get_track(capture)
                tracks[track_id] = track
                self.logger.debug(f"Found track with ID: {track_id}")

        except StopIteration:
            pass

        assert (
            stream_name is not None and sdp is not None and tracks
        ), "Error parsing RSTP"
        return stream_name, sdp, tracks

    def _get_sdp(self, capture: FileCapture) -> Tuple[str, dict]:
        while True:
            request = capture.next()
            if hasattr(request.rtsp, "method") and request.rtsp.method == "DESCRIBE":
                break

        response = capture.next()
        stream_url = request.rtsp.url
        sdp = sdp_transform.parse(bytes.fromhex(response.rtsp.data.raw_value).decode())
        return stream_url, sdp

    def _get_track(self, capture: FileCapture) -> Dict[str, RTSPTrack]:
        while True:
            request = capture.next()
            if hasattr(request.rtsp, "method") and request.rtsp.method == "SETUP":
                break

        response = capture.next()
        track_id = request.rtsp.url
        transport = RTSPTransportHeader.parse(response.rtsp.transport)
        assert (
            transport.protocol == "RTP/AVP"
        ), f"Only RTP/AVP is supported, Got {transport_protocol}"
        server_ip = str(response.ip.src)
        client_port, _ = transport.options["client_port"].split("-", 1)
        server_port, _ = transport.options["server_port"].split("-", 1)
        assert "source" not in transport.options, "Different source is not supported"

        track = RTSPTrack(
            server_ip=server_ip,
            server_port=int(server_port),
            client_port=int(client_port),
        )

        return track_id, track
