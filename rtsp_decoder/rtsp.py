from enum import Enum
import logging

from dpkt.pcap import UniversalReader
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.tcp import TCP, TH_FIN, TH_URG
from dpkt.udp import UDP
from dpkt.rtp import RTP
from dpkt.utils import inet_to_str

import sdp_transform

from rtsp_decoder.rtsp_session import (
    RTSPSession,
    RTSPSessionState,
    RTSP_PORTS,
    RTSPTransportHeader,
)
from rtsp_decoder.sdp import get_sdp_medias, get_payload_type_from_sdp_media
from rtsp_decoder.task import (
    Task,
    TaskType,
    CreateDecoderTaskBody,
    ProcessRTPPacketTaskBody,
)
from rtsp_decoder.rtp_packet import RTPPacket

from typing import NamedTuple, Dict, Tuple, List, Optional, Iterator, Set


class IPProto(Enum):
    TCP = 6
    UDP = 17


class FiveTuple(NamedTuple):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: IPProto

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


RTPID = Tuple[FiveTuple, int, int]  # Five tuple, ssrc and payload type


class RTSPDataExtractor:
    """
    Find the first RTSP stream, and extract from it the stream name, the sdp and the tracks
    """

    def __init__(self, pcap_path: str):
        self.logger = logging.getLogger(__name__)
        self._pcap_path: str = pcap_path
        self._current_ident: int = 0
        self._rtp_id_to_ident: Dict[RTPID, int] = {}
        self._rtp_over_tcp_sessions: Dict[FiveTuple, RTSPSession] = {}
        self._rtp_over_udp_sessions: Dict[FiveTuple, RTSPSession] = {}
        self._invalid_five_tuples: Set[FiveTuple] = set()
        self._done_rtsp_five_tuples: Set[FiveTuple] = set()

    def process_next(self) -> Iterator[Task]:
        rtsp_sessions: Dict[FiveTuple, RTSPSession] = {}

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
                if not isinstance(ip_layer.data, TCP):
                    continue

                if ip_layer.data.sport not in RTSP_PORTS:
                    continue

                five_tuple = FiveTuple.from_dpkt(ip_layer)
                if five_tuple in self._rtp_over_tcp_sessions:
                    rtsp_session = self._rtp_over_tcp_sessions[five_tuple]
                    rtsp_session.process_packet(ip_layer)
                    yield from self._process_rtp_over_tcp(five_tuple, rtsp_session)
                    continue

                if five_tuple in self._done_rtsp_five_tuples:
                    continue

                if five_tuple not in rtsp_sessions:
                    rtsp_sessions[five_tuple] = RTSPSession()

                rtsp_session = rtsp_sessions[five_tuple]
                rtsp_session.process_packet(ip_layer)
                if rtsp_session.state == RTSPSessionState.DONE:
                    self._handle_rtsp_session(five_tuple, rtsp_session)

            # Finish handling all the tcp sessions
            for five_tuple, rtsp_session in rtsp_sessions.items():
                if five_tuple in self._done_rtsp_five_tuples:
                    continue

                rtsp_session.process_packet(None)
                self._handle_rtsp_session(five_tuple, rtsp_session)
                if five_tuple in self._rtp_over_tcp_sessions:
                    yield from self._process_rtp_over_tcp(five_tuple, rtsp_session)

            # Reiterate over the capture to handle all the UDP streams.
            # The reason we need another iteration is so we don't miss
            # any packets because the TCP reassembly didn't catch up
            # to the processing.
            f.seek(0)
            capture = UniversalReader(f)
            for timestamp, buf in capture:
                # Assume layer 2 is Ethernet
                eth_layer = Ethernet(buf)

                if not isinstance(eth_layer.data, IP):
                    continue

                ip_layer = eth_layer.data
                if not isinstance(ip_layer.data, UDP):
                    continue

                five_tuple = FiveTuple.from_dpkt(ip_layer)
                if five_tuple in self._invalid_five_tuples:
                    continue

                if five_tuple not in self._rtp_over_udp_sessions:
                    continue

                rtsp_session = self._rtp_over_udp_sessions[five_tuple]
                if (
                    inet_to_str(ip_layer.src) != rtsp_session.server_ip
                    or inet_to_str(ip_layer.dst) != rtsp_session.client_ip
                ):
                    continue

                udp_layer = ip_layer.data

                try:
                    dpkt_rtp = RTP(udp_layer.data)
                except Exception as e:
                    self.logger.error(f"Could not parse RTP packet: {e}")
                    continue

                rtp_packet = RTPPacket.from_dpkt(dpkt_rtp)
                yield from self._handle_rtp_packet(rtsp_session, five_tuple, rtp_packet)

    def _handle_rtsp_session(
        self, five_tuple: FiveTuple, rtsp_session: RTSPSession
    ) -> None:
        if rtsp_session.sdp is None:
            return

        expected_transport_headers = len(get_sdp_medias(rtsp_session.sdp))
        if len(rtsp_session.transport_headers) < expected_transport_headers:
            return

        # For each track, transport is either UDP or TCP.
        # We handle each transport header and then delete it and the RTSP Session too
        # if we can.
        for transport_header in rtsp_session.transport_headers:
            transport_header: RTSPTransportHeader
            try:
                # If it is TCP, we need to mark this RTSP session as one that we
                # extract RTP packets from, and what channels are relevant.
                # Once we actually get an RTP packet that is relevant, we can take the
                # five tuple, SSRC and payload type and find the SDP media associated with it.
                if transport_header.protocol == "rtp/avp/tcp":
                    data_channel, control_channel = self._parse_rtp_optional_range(
                        transport_header.options["interleaved"]
                    )
                    if five_tuple not in self._rtp_over_tcp_sessions:
                        self._rtp_over_tcp_sessions[five_tuple] = rtsp_session

                    rtsp_session.data_channels.append(data_channel)

                    if control_channel is not None:
                        rtsp_session.control_channels.append(control_channel)

                # If it is UDP, we need to start parsing that five tuple as RTP.
                # Once we actually get an RTP over UDP packet, we can take the five tuple,
                # SSRC and paylaod type and find the original RTSP session and SDP media
                # associated with it.
                elif transport_header.protocol in ("rtp/avp", "rtp/avp/udp"):
                    client_port, _ = self._parse_rtp_optional_range(
                        transport_header.options["client_port"]
                    )
                    server_port, _ = self._parse_rtp_optional_range(
                        transport_header.options["server_port"]
                    )
                    rtp_five_tuple = FiveTuple(
                        src_ip=rtsp_session.server_ip,
                        dst_ip=rtsp_session.client_ip,
                        src_port=server_port,
                        dst_port=client_port,
                        proto=IPProto.UDP,
                    )
                    self._rtp_over_udp_sessions[rtp_five_tuple] = rtsp_session
                else:
                    self.logger.error(
                        f"Tranport protocol {transport_header.protocol} not supported"
                    )
            except Exception as e:
                self.logger.error(f"Invalid transport header: {e}")

        rtsp_session.transport_headers.clear()
        self._done_rtsp_five_tuples.add(five_tuple)

    def _process_rtp_over_tcp(
        self,
        five_tuple: FiveTuple,
        rtsp_session: RTSPSession,
    ) -> Iterator[Task]:
        for rtp_packet in rtsp_session.get_rtp():
            yield from self._handle_rtp_packet(rtsp_session, five_tuple, rtp_packet)

    def _handle_rtp_packet(
        self, rtsp_session: RTSPSession, five_tuple: FiveTuple, rtp_packet: RTPPacket
    ) -> Iterator[Task]:
        rtpid = (five_tuple, rtp_packet.ssrc, rtp_packet.payload_type)
        try:
            ident = self._rtp_id_to_ident[rtpid]
        except KeyError:
            sdp_media = self._get_sdp_media_for_rtp_stream(
                rtsp_session.sdp, rtp_packet.payload_type
            )

            if sdp_media is None:
                self.logger.error(
                    "Could not find SDP media of RTP stream in SDP, discarding stream"
                )
                self._invalid_five_tuples.add(five_tuple)
                return

            ident = self._get_next_ident()
            create_decoder = CreateDecoderTaskBody(ident=ident, sdp_media=sdp_media)
            create_task = Task(ttype=TaskType.CREATE_DECODER, body=create_decoder)
            yield create_task
            self._rtp_id_to_ident[rtpid] = ident

        process_rtp_packet = ProcessRTPPacketTaskBody(
            ident=ident, rtp_packet=rtp_packet
        )
        process_task = Task(ttype=TaskType.PROCESS_RTP_PACKET, body=process_rtp_packet)
        yield process_task

    @staticmethod
    def _parse_rtp_optional_range(optional_range_str: str) -> Tuple[int, Optional[int]]:
        first_num_str = optional_range_str
        second_num_str = None
        if "-" in optional_range_str:
            first_num_str, second_num_str = optional_range_str.split("-", 1)

        first_num = int(first_num_str)
        second_num = None
        if second_num_str is not None:
            second_num = int(second_num_str)

        return first_num, second_num

    def _get_next_ident(self) -> int:
        ident = self._current_ident
        self._current_ident += 1
        return ident

    @staticmethod
    def _get_sdp_media_for_rtp_stream(sdp: dict, payload_type: int) -> Optional[dict]:
        for sdp_media in get_sdp_medias(sdp):
            if get_payload_type_from_sdp_media(sdp_media) == payload_type:
                return sdp_media
