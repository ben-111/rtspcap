from enum import Enum
from dataclasses import dataclass, field

from pyshark import FileCapture
from pyshark.packet.packet import Packet

from dpkt.pcap import UniversalReader
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.tcp import TCP, TH_FIN, TH_URG
from dpkt.udp import UDP
from dpkt.rtp import RTP
from dpkt.utils import inet_to_str

import sdp_transform

from rtsp_decoder.rtsp_session import RTSPSession, RTSPSessionState, RTSP_PORTS
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

    @classmethod
    def from_dpkt(cls, ip_layer: IP) -> "FiveTuple":
        assert isinstance(ip_layer.data, TCP) or isinstance(ip_layer.data, UDP)

        transport_layer = ip_layer.data
        if isinstance(ip_layer.data, TCP):
            proto = IPProto.TCP
        else:
            proto = IPProto.UDP

        return cls(
            src_ip=inet_to_str(ip_layer.src),
            dst_ip=inet_to_str(ip_layer.dst),
            src_port=transport_layer.sport,
            dst_port=transport_layer.dport,
            proto=proto,
        )


class RTSPDataExtractor:
    """
    Find the first RTSP stream, and extract from it the stream name, the sdp and the tracks
    """

    def __init__(self, pcap_path: str, backup_sdp: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self._pcap_path: str = pcap_path
        self._backup_sdp: Optional[str] = backup_sdp
        self._current_ident: int = 0

    def is_rtsp(self, ip_layer: IP) -> bool:
        if not isinstance(ip_layer.data, TCP):
            return False

        tcp_layer = ip_layer.data
        if tcp_layer.sport not in RTSP_PORTS or tcp_layer.dport not in RTSP_PORTS:
            return False

        return True

    def process_next(self) -> Iterator[Task]:
        ssrc_to_ident: Dict[int, int] = {}
        rtsp_sessions: Dict[FiveTuple, RTSPSession] = {}
        invalid_ssrcs: List[int] = []

        with open(self._pcap_path, "rb") as f:
            capture = UniversalReader(f)
            timestamp: float
            buf: bytes
            for timestamp, buf in capture:
                # Assume layer 2 is Ethernet
                eth_layer = Ethernet(buf)

                if not isinstance(eth_layer.data, IP):
                    continue

                ip_layer = eth_layer.data
                if isinstance(ip_layer.data, TCP):
                    five_tuple = FiveTuple.from_dpkt(ip_layer)
                    tcp = ip_layer.data

                    if five_tuple not in rtsp_sessions:
                        rtsp_sessions[five_tuple] = RTSPSession()

                    rtsp_session = rtsp_sessions[five_tuple]
                    rtsp_session.process_packet(tcp)
                    if rtsp_session.state == RTSPSessionState.DONE:
                        self._handle_rtsp_session(rtsp_session)

                elif isinstance(ip_layer.data, UDP):
                    ...
                else:
                    continue

            for rtsp_session in rtsp_sessions.values():
                rtsp_session.process_packet(None)
                self._handle_rtsp_session(rtsp_session)

        return
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

    def _handle_rtsp_session(self, rtsp_session: RTSPSession) -> None:
        ...

    def _get_next_ident(self) -> int:
        ident = self._current_ident
        self._current_ident += 1
        return ident

    @classmethod
    def _find_rtsp_stream(
        cls,
        ssrc: int,
        five_tuple: FiveTuple,
        rtsp_sessions: Dict[FiveTuple, RTSPSession],
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
