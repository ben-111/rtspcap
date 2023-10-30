from os.path import basename
from urllib.parse import urlparse

from pyshark import FileCapture
import sdp_transform

from typing import NamedTuple, Dict, Tuple, List, Union, Optional

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
            options[key.casefold()] = value

        return cls(protocol=protocol, options=options)


class RTPInfo(NamedTuple):
    rtptime: Optional[int]
    seq: Optional[int]


class TransportInformation(NamedTuple):
    transport_header: RTSPTransportHeader
    server_ip: str
    client_ip: str
    rtsp_tcp_stream_num: int
    transport_specific_data: Union[None, RTPInfo] = None


class RTSPDataExtractor:
    """
    Find the first RTSP stream, and extract from it the stream name, the sdp and the tracks
    """

    def __init__(self, pcap_path: str):
        self.logger = logging.getLogger(__name__)
        self.stream_name = None
        self.sdp = None
        self.tracks: Dict[str, TransportInformation] = dict()

        # Currently only taking the first stream we find
        with FileCapture(pcap_path, display_filter=f"rtsp") as cap:
            try:
                first_rtsp = cap.next()
            except StopIteration:
                raise ValueError("Could not find RTSP stream")

        assert "IP" in first_rtsp, "TCP" in first_rtsp
        self.logger.debug(
            f"Found RTSP stream: {first_rtsp['IP'].src}:{first_rtsp['TCP'].srcport}"
            + f" <--> {first_rtsp['IP'].dst}:{first_rtsp['TCP'].dstport}"
        )
        tcp_stream = first_rtsp["TCP"].stream

        # We disable sdp so we can access the SDP data directly
        with FileCapture(
            pcap_path,
            display_filter=f"tcp.stream == {tcp_stream} and (rtsp.request or rtsp.response)",
            disable_protocol="sdp",
        ) as cap:
            (
                self.stream_name,
                self.sdp,
                self.tracks,
                self.rtp_info,
            ) = self._extract_rtsp_data(cap)

    def _extract_rtsp_data(
        self, capture: FileCapture
    ) -> Tuple[str, dict, Dict[str, TransportInformation]]:
        stream_name = None
        sdp = None
        tracks: Dict[str, RTSPTrack] = dict()
        try:
            stream_url, sdp = self._get_sdp(capture)
            stream_name = basename(urlparse(stream_url).path)
            self.logger.debug(f"Found SDP, stream url is {stream_url}")

            number_of_tracks = len(sdp["media"])

            while True:
                track_id, transport_info = self._get_track(capture)
                tracks[track_id] = transport_info
                self.logger.debug(f"Found track with ID: {track_id}")
                if len(tracks) == number_of_tracks:
                    break

            rtp_info = self._get_rtp_info(capture)
            for track_id, track_rtp_info in rtp_info.items():
                if track_id in tracks:
                    rtptime = (
                        int(track_rtp_info["rtptime"])
                        if "rtptime" in track_rtp_info
                        else None
                    )
                    seq = (
                        int(track_rtp_info["seq"]) if "seq" in track_rtp_info else None
                    )
                    rtp_info_obj = RTPInfo(rtptime=rtptime, seq=seq)
                    tracks[track_id].transport_specific_data = rtp_info_obj

        except StopIteration:
            pass

        assert (
            stream_name is not None and sdp is not None and tracks
        ), "Error parsing RSTP"
        return stream_name, sdp, tracks, rtp_info

    def _get_sdp(self, capture: FileCapture) -> Tuple[str, dict]:
        while True:
            request = capture.next()
            if (
                "RTSP" in request
                and request["RTSP"].has_field("method")
                and request["RTSP"].method == "DESCRIBE"
            ):
                break

        response = capture.next()
        stream_url = request.rtsp.url
        sdp = sdp_transform.parse(bytes.fromhex(response.rtsp.data.raw_value).decode())
        return stream_url, sdp

    def _get_track(
        self, capture: FileCapture
    ) -> Tuple[str, Dict[str, TransportInformation]]:
        while True:
            request = capture.next()
            if (
                "RTSP" in request
                and request["RTSP"].has_field("method")
                and request["RTSP"].method == "SETUP"
            ):
                response = capture.next()
                if "RTSP" in response and response["RTSP"].has_field("transport"):
                    break

        track_id = request["RTSP"].url
        transport_header = RTSPTransportHeader.parse(response["RTSP"].transport)

        assert "IP" in response, "TCP" in response
        transport_info = TransportInformation(
            transport_header=transport_header,
            server_ip=response["IP"].src,
            client_ip=response["IP"].dst,
            rtsp_tcp_stream_num=response["TCP"].stream,
        )

        return track_id, transport_info

    def _get_rtp_info(self, capture: FileCapture) -> Dict[str, Dict[str, str]]:
        while True:
            request = capture.next()
            if (
                "RTSP" not in request
                or not request["RTSP"].has_field("method")
                or not request["RTSP"].method == "PLAY"
            ):
                continue

            response = capture.next()
            if "RTSP" not in response or "TCP" not in response:
                continue

            response_bytes = bytes.fromhex(response["TCP"].payload.raw_value)
            response_str = response_bytes.decode()
            for line in response_str.splitlines():
                if line.startswith("RTSP/"):
                    continue

                # Line is a header
                assert ":" in line, "Malformed RTSP response"
                header_name, header_value = line.split(": ", 1)
                header_name = header_name.casefold()
                if header_name == "rtp-info":
                    return self._parse_rtp_info_header(header_value)

    def _parse_rtp_info_header(self, header_value: str) -> Dict[str, Dict[str, str]]:
        err_msg = "Malformed RTP-Info header"
        rtp_info = dict()
        for track_info in header_value.split(","):
            attributes = track_info.split(";")
            assert len(attributes) > 1, err_msg
            url_name, url_value = attributes[0].split("=", 1)
            assert url_name == "url", err_msg
            rtp_info[url_value] = dict()
            for attribute in attributes[1:]:
                assert "=" in attribute, err_msg
                key, value = attribute.split("=", 1)
                rtp_info[url_value][key] = value

        return rtp_info
