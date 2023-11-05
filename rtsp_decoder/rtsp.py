from enum import Enum
from dataclasses import dataclass, field

from pyshark import FileCapture
from pyshark.packet.packet import Packet
import sdp_transform

from rtsp_decoder.sdp import get_sdp_medias, get_payload_type_from_sdp_media
from rtsp_decoder.task import (
    Task,
    TaskType,
    CreateDecoderTaskBody,
    ProcessRTPPacketTaskBody,
)
from rtsp_decoder.rtp_packet import RTPPacket

from typing import NamedTuple, Dict, Tuple, List, Optional, Iterator

import logging


class RTSPTransportHeader(NamedTuple):
    protocol: str
    options: Dict[str, str]

    @classmethod
    def parse(cls, header_str: str) -> "RTSPTransportHeader":
        transport_header_values = header_str.split(";")
        protocol = transport_header_values[0].casefold()
        options = dict()
        for option in transport_header_values[1:]:
            key, value = option.split("=", 1) if "=" in option else (option, None)
            options[key.casefold()] = value

        return cls(protocol=protocol, options=options)


class IPProto(Enum):
    TCP = 6
    UDP = 17


class FiveTuple(NamedTuple):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: IPProto

    def __eq__(self, other: "FiveTuple") -> bool:
        return self.__hash__() == other.__hash__()

    def __hash__(self) -> int:
        peer1 = f"{self.src_ip}:{self.src_port}"
        peer2 = f"{self.dst_ip}:{self.dst_port}"
        hash_str = ",".join(sorted([peer1, peer2]))
        return hash((hash_str, self.proto))

    @classmethod
    def from_pyshark(cls, packet: Packet) -> "FiveTuple":
        assert "IP" in packet and ("TCP" in packet or "UDP" in packet)
        if "TCP" in packet:
            proto = IPProto.TCP
            transport_layer = packet["TCP"]
        else:
            proto = IPProto.UDP
            transport_layer = packet["UDP"]

        return cls(
            src_ip=str(packet["IP"].src),
            dst_ip=str(packet["IP"].dst),
            src_port=int(transport_layer.srcport),
            dst_port=int(transport_layer.dstport),
            proto=proto,
        )


@dataclass
class RTSPSessionInfo:
    sdp: Optional[dict] = None
    transport_headers: List[RTSPTransportHeader] = field(default_factory=list)


class RTSPDataExtractor:
    """
    Find the first RTSP stream, and extract from it the stream name, the sdp and the tracks
    """

    def __init__(self, pcap_path: str, backup_sdp: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self._pcap_path: str = pcap_path
        self._backup_sdp: Optional[str] = backup_sdp
        self._current_ident: int = 0

    def process_next(self) -> Iterator[Task]:
        ssrc_to_ident: Dict[int, int] = {}
        rtsp_sessions: Dict[FiveTuple, RTSPSessionInfo] = {}
        invalid_ssrcs: List[int] = []

        # We disable sdp so we can access the SDP data directly
        with FileCapture(
            self._pcap_path,
            display_filter=f"(rtsp.request or rtsp.response) or (rtp.ssrc and rtp.p_type != 0)",
            disable_protocol="sdp",
        ) as capture:
            for packet in capture:
                if (
                    "RTP" in packet
                    and packet["RTP"].has_field("ssrc")
                    and packet["RTP"].has_field("p_type")
                    and packet["RTP"].has_field("payload")
                ):
                    rtp_layer = packet["RTP"]
                    ssrc = int(rtp_layer.ssrc, 16)

                    if ssrc in invalid_ssrcs:
                        continue

                    payload_type = int(rtp_layer.p_type)
                    try:
                        ident = ssrc_to_ident[ssrc]
                        rtp_packet = RTPPacket.from_pyshark(packet)
                        process_rtp_packet = ProcessRTPPacketTaskBody(
                            ident=ident, rtp_packet=rtp_packet
                        )
                        task = Task(
                            ttype=TaskType.PROCESS_RTP_PACKET, body=process_rtp_packet
                        )
                        yield task
                    except KeyError:
                        rtsp_five_tuple, th_index = self._find_rtsp_stream(
                            ssrc, FiveTuple.from_pyshark(packet), rtsp_sessions
                        )
                        if rtsp_five_tuple is None:
                            self.logger.error(
                                "Could not associate RTP packet with an RTSP stream, discarding it"
                            )
                            continue

                        if rtsp_sessions[rtsp_five_tuple].sdp is None:
                            if self._backup_sdp is None:
                                self.logger.error(
                                    f"Could not find SDP of RTP stream with ssrc {ssrc}, discarding stream"
                                )
                                invalid_ssrcs.append(ssrc)
                                continue

                            self.logger.warning(
                                f"Could not find SDP of RTP stream with ssrc {ssrc}, using backup SDP"
                            )
                            rtsp_sessions[rtsp_five_tuple].sdp = self._backup_sdp

                        rtsp_sessions[rtsp_five_tuple].transport_headers.pop(th_index)
                        rtsp_session = rtsp_sessions[rtsp_five_tuple]
                        if not rtsp_session.transport_headers:
                            rtsp_sessions.pop(rtsp_five_tuple)

                        sdp_media = self._get_sdp_media_for_rtp_stream(
                            rtsp_session.sdp, payload_type
                        )

                        if sdp_media is None:
                            self.logger.error(
                                "Could not find SDP media of RTP stream in SDP, discarding stream"
                            )
                            invalid_ssrcs.append(ssrc)
                            continue

                        ident = self._get_next_ident()
                        create_decoder = CreateDecoderTaskBody(
                            ident=ident, sdp_media=sdp_media
                        )
                        create_task = Task(
                            ttype=TaskType.CREATE_DECODER, body=create_decoder
                        )
                        yield create_task
                        ssrc_to_ident[ssrc] = ident

                        rtp_packet = RTPPacket.from_pyshark(packet)
                        process_rtp_packet = ProcessRTPPacketTaskBody(
                            ident=ident, rtp_packet=rtp_packet
                        )
                        process_task = Task(
                            ttype=TaskType.PROCESS_RTP_PACKET, body=process_rtp_packet
                        )
                        yield process_task

                elif "TCP" in packet and "RTSP" in packet:
                    five_tuple = FiveTuple.from_pyshark(packet)
                    if five_tuple not in rtsp_sessions:
                        rtsp_sessions[five_tuple] = RTSPSessionInfo()

                    if (
                        packet["RTSP"].has_field("data")
                        and packet["RTSP"].has_field("content_type")
                        and packet["RTSP"].content_type.casefold() == "application/sdp"
                    ):
                        sdp = sdp_transform.parse(
                            bytes.fromhex(packet["RTSP"].data.raw_value).decode()
                        )
                        rtsp_sessions[five_tuple].sdp = sdp

                    if (
                        packet["RTSP"].has_field("transport")
                        and packet["RTSP"].has_field("status")
                        and int(packet["RTSP"].status) == 200
                    ):
                        transport_header = RTSPTransportHeader.parse(
                            packet["RTSP"].transport
                        )
                        rtsp_sessions[five_tuple].transport_headers.append(
                            transport_header
                        )

    def _get_next_ident(self) -> int:
        ident = self._current_ident
        self._current_ident += 1
        return ident

    @classmethod
    def _find_rtsp_stream(
        cls,
        ssrc: int,
        five_tuple: FiveTuple,
        rtsp_sessions: Dict[FiveTuple, RTSPSessionInfo],
    ) -> Tuple[Optional[FiveTuple], int]:
        """
        Associate an RTP stream with an RTSP stream using the transport headers in
        the RTSP stream.
        """
        for rtsp_five_tuple, rtsp_session in rtsp_sessions.items():
            for i, transport in enumerate(rtsp_session.transport_headers):
                if (
                    "ssrc" in transport.options
                    and int(transport.options["ssrc"], 16) == ssrc
                ):
                    return rtsp_five_tuple, i

                if transport.protocol == "rtp/avp/tcp":
                    # RTP packets will be sent on the same tcp session as the RTSP
                    if rtsp_five_tuple == five_tuple:
                        return rtsp_five_tuple, i
                else:
                    assert (
                        "client_port" in transport.options
                        and "server_port" in transport.options
                    )
                    client_port = cls._parse_transport_port(
                        transport.options["client_port"]
                    )
                    server_port = cls._parse_transport_port(
                        transport.options["server_port"]
                    )
                    transport_tuple = FiveTuple(
                        src_ip=five_tuple.src_ip,
                        dst_ip=five_tuple.dst_ip,
                        src_port=server_port,
                        dst_port=client_port,
                        proto=IPProto.UDP,
                    )
                    if transport_tuple == five_tuple:
                        return rtsp_five_tuple, i

        return None, -1

    @staticmethod
    def _parse_transport_port(port_range: str) -> int:
        port_str, _ = port_range.split("-", 1)
        return int(port_str)

    @staticmethod
    def _get_sdp_media_for_rtp_stream(sdp: dict, payload_type: int) -> Optional[dict]:
        for sdp_media in get_sdp_medias(sdp):
            if get_payload_type_from_sdp_media(sdp_media) == payload_type:
                return sdp_media
