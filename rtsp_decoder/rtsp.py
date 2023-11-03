from dataclasses import dataclass, field

from os.path import basename
from urllib.parse import urlparse

from pyshark import FileCapture
from pyshark.packet.packet import Packet
import sdp_transform

from rtsp_decoder.sdp import get_sdp_medias, get_payload_type_from_sdp_media

from typing import NamedTuple, Dict, Tuple, List, Optional

import logging

TypeSSRC = int


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


class FourTuple(NamedTuple):
    ips: str = ""
    ports: str = ""

    @classmethod
    def create(
        cls, src_ip: str, dst_ip: str, src_port: int, dst_port: int
    ) -> "FourTuple":
        ips = ":".join(sorted([src_ip, dst_ip]))
        ports = ":".join(sorted([str(src_port), str(dst_port)]))
        return cls(ips=ips, ports=ports)


@dataclass
class RTSPSessionInfo:
    first_frame_number: int = -1
    sdp: Optional[dict] = None
    transport_headers: List[RTSPTransportHeader] = field(default_factory=list)


@dataclass
class RTPStreamInfo:
    payload_type: int = -1
    first_frame_number: int = -1
    sdp_media: Optional[dict] = None


class RTSPDataExtractor:
    """
    Find the first RTSP stream, and extract from it the stream name, the sdp and the tracks
    """

    def __init__(self, pcap_path: str, backup_sdp: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.streams = self._extract_rtsp_data(pcap_path, backup_sdp)

    def _extract_rtsp_data(
        self, pcap_path: str, backup_sdp: Optional[str] = None
    ) -> Dict[TypeSSRC, RTPStreamInfo]:
        # We disable sdp so we can access the SDP data directly
        with FileCapture(
            pcap_path,
            display_filter=f"(rtsp.request or rtsp.response) or (rtp.ssrc and rtp.p_type != 0)",
            disable_protocol="sdp",
        ) as capture:
            streams, rtsp_sessions = self._extract_data_from_capture(capture)

        if not streams:
            self.logger.error("No RTP streams found")
            return streams

        for key, rtsp_session in rtsp_sessions.copy().items():
            if rtsp_session.sdp is None:
                self.logger.warning("Found RTSP session without SDP file")
                rtsp_sessions.pop(key)

        if not rtsp_sessions:
            if backup_sdp is None:
                self.logger.error(
                    "No RTSP sessions found; Consider providing an SDP file"
                )
                return {}
            else:
                self.logger.warning("No RTSP sessions found; Using provided SDP file")
                sdp = sdp_transform.parse(backup_sdp)
                fake_rtsp_session = RTSPSessionInfo(sdp=sdp)
                fake_four_tuple = FourTuple()
                rtsp_sessions[fake_four_tuple] = fake_rtsp_session

        out_streams = streams.copy()
        for ssrc, stream_info in streams.items():
            four_tuple = self._associate_rtp_stream_with_rtsp_stream(
                ssrc, stream_info, rtsp_sessions
            )
            sdp_media = self._get_sdp_media_for_rtp_stream(
                rtsp_sessions[four_tuple].sdp, stream_info
            )
            if sdp_media is None:
                self.logger.error(
                    f"Failed to get SDP media for RTP stream with SSRC of {ssrc}; Discarding this stream"
                )
                out_streams.pop(ssrc)
                continue

            out_streams[ssrc].sdp_media = sdp_media

        return out_streams

    def _extract_data_from_capture(
        self, capture: FileCapture
    ) -> Tuple[Dict[TypeSSRC, RTPStreamInfo], Dict[FourTuple, RTSPSessionInfo]]:
        streams: Dict[TypeSSRC, RTPStreamInfo] = {}
        rtsp_sessions: Dict[FourTuple, RTSPSessionInfo] = {}
        for packet in capture:
            if "TCP" in packet and "RTSP" in packet:
                four_tuple = self._get_tcp_four_tuple(packet)
                if four_tuple not in rtsp_sessions:
                    rtsp_sessions[four_tuple] = RTSPSessionInfo(
                        first_frame_number=int(packet.frame_info.number)
                    )

                if (
                    packet["RTSP"].has_field("data")
                    and packet["RTSP"].has_field("content_type")
                    and packet["RTSP"].content_type.casefold() == "application/sdp"
                ):
                    sdp = sdp_transform.parse(
                        bytes.fromhex(packet["RTSP"].data.raw_value).decode()
                    )
                    rtsp_sessions[four_tuple].sdp = sdp

                if (
                    packet["RTSP"].has_field("transport")
                    and packet["RTSP"].has_field("status")
                    and int(packet["RTSP"].status) == 200
                ):
                    transport_header = RTSPTransportHeader.parse(
                        packet["RTSP"].transport
                    )
                    rtsp_sessions[four_tuple].transport_headers.append(transport_header)

            if (
                "RTP" in packet
                and packet["RTP"].has_field("ssrc")
                and packet["RTP"].has_field("p_type")
            ):
                stream_id = int(packet["RTP"].ssrc, 16)
                if stream_id in streams:
                    continue

                streams[stream_id] = RTPStreamInfo(
                    payload_type=int(packet["RTP"].p_type),
                    first_frame_number=int(packet.frame_info.number),
                )

        return streams, rtsp_sessions

    def _associate_rtp_stream_with_rtsp_stream(
        self,
        ssrc: TypeSSRC,
        stream_info: RTPStreamInfo,
        rtsp_sessions: Dict[FourTuple, RTSPSessionInfo],
    ) -> FourTuple:
        """
        Try and associate each RTP stream with an SDP media using a number
        of techniques, from the most accurate to the least.

        The techniques in order of accuracy (best is first):
        1. SSRC association from transport headers
        2. Taking the last rtsp session from packet order
        3. Taking the next rtsp session from packet order
        """
        four_tuple = self._find_rtsp_session_by_ssrc(rtsp_sessions, ssrc)
        if four_tuple is not None:
            return four_tuple

        self.logger.debug("Could not associate RTP stream by SSRC, using proximity")
        four_tuple = self._find_rtsp_session_by_proximity(
            rtsp_sessions, stream_info.first_frame_number
        )

        return four_tuple

    def _find_rtsp_session_by_ssrc(
        self, rtsp_sessions: Dict[FourTuple, RTSPSessionInfo], ssrc: TypeSSRC
    ) -> Optional[FourTuple]:
        for four_tuple, session_info in rtsp_sessions.items():
            if not session_info.transport_headers:
                continue

            for transport_header in session_info.transport_headers:
                if (
                    "ssrc" in transport_header.options
                    and int(transport_header.options["ssrc"], 16) == ssrc
                ):
                    return four_tuple

    def _find_rtsp_session_by_proximity(
        self, rtsp_sessions: Dict[FourTuple, RTSPSessionInfo], frame_number: int
    ) -> Optional[FourTuple]:
        assert rtsp_sessions
        rtsp_sessions_by_frame_num = sorted(
            [
                (four_tuple, session_info)
                for four_tuple, session_info in rtsp_sessions.items()
            ],
            key=lambda x: x[1].first_frame_number,
        )
        closest_rtsp_session_four_tuple = None
        for four_tuple, rtsp_session in rtsp_sessions_by_frame_num:
            session_frame_number = rtsp_session.first_frame_number
            if frame_number < session_frame_number:
                break

            closest_rtsp_session_four_tuple = four_tuple

        if closest_rtsp_session_four_tuple is not None:
            return closest_rtsp_session_four_tuple

        self.logger.debug(
            "Could not find SDP before the start of the RTP stream, using SDP file found after the stream"
        )
        for four_tuple, rtsp_session in reversed(rtsp_sessions_by_frame_num):
            session_frame_number = rtsp_session.first_frame_number
            if frame_number > session_frame_number:
                break

            closest_rtsp_session_four_tuple = four_tuple

        if closest_rtsp_session_four_tuple is None:
            self.logger.warning(
                "This should be impossible, choosing first RTSP session"
            )
            closest_rtsp_session_four_tuple = list(rtsp_sessions.keys())[0]

        return closest_rtsp_session_four_tuple

    def _get_sdp_media_for_rtp_stream(
        self, sdp: dict, stream_info: RTPStreamInfo
    ) -> Optional[dict]:
        payload_type = stream_info.payload_type
        for sdp_media in get_sdp_medias(sdp):
            if get_payload_type_from_sdp_media(sdp_media) == payload_type:
                return sdp_media

    @staticmethod
    def _get_tcp_four_tuple(packet: Packet) -> FourTuple:
        assert "IP" in packet and "TCP" in packet
        return FourTuple.create(
            src_ip=str(packet["IP"].src),
            dst_ip=str(packet["IP"].dst),
            src_port=int(packet["TCP"].srcport),
            dst_port=int(packet["TCP"].dstport),
        )
