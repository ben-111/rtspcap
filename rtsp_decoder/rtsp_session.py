from enum import Enum
import logging

from dpkt.ip import IP
from dpkt.tcp import TCP, TH_URG, TH_FIN
from dpkt.rtp import RTP
from dpkt.utils import inet_to_str
from dpkt.dpkt import UnpackError, NeedData

import sdp_transform

from rtsp_decoder.reassembler import Reassembler, EmptyQueueException
from rtsp_decoder.dpkt_helpers.rtsp import RTSPResponse
from rtsp_decoder.sdp import get_sdp_medias
from rtsp_decoder.rtp_packet import RTPPacket

from typing import NamedTuple, Optional, Dict, Iterator, List, Tuple

TCP_SEQ_SIZE_IN_BITS = 4 * 8
RTSP_PORTS = (554, 8554, 7236)  # Taken from wireshark
MIN_RTP_SIZE = 12
MAX_RTP_SIZE = 8192
INTERLEAVED_HEADER_LEN = 4
INTERLEAVED_HEADER_MAGIC = 0x24


class RTSPTransportHeader(NamedTuple):
    protocol: str
    options: Dict[str, str]

    @classmethod
    def parse(cls, header_str: str) -> "RTSPTransportHeader":
        transport_header_values = header_str.split(";")
        protocol = transport_header_values[0].casefold()
        options = {}
        for option in transport_header_values[1:]:
            key, value = option.split("=", 1) if "=" in option else (option, None)
            options[key.casefold()] = value

        return cls(protocol=protocol, options=options)


class RTSPSessionState(Enum):
    PROCESSING_RTSP = 0
    RTSP_READY = 1
    PROCESSING_RTP = 2
    DONE = 3
    INVALID = 4


class RTSPSession:
    MAX_OUT_OF_ORDER = 30

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.server_ip: Optional[str] = None
        self.client_ip: Optional[str] = None
        self.sdp: Optional[dict] = None
        self.transport_headers: List[RTSPTransportHeader] = []
        self.control_channels: List[int] = []
        self.data_channels: List[int] = []
        self._reassembler = Reassembler[bytes](
            TCP_SEQ_SIZE_IN_BITS, self.MAX_OUT_OF_ORDER, "data"
        )
        self._state: RTSPSessionState = RTSPSessionState.PROCESSING_RTSP
        self._buffer: bytes = b""
        self._current_channel: int = -1
        self._current_rtp_length: int = -1

    @property
    def state(self) -> RTSPSessionState:
        return self._state

    def process_packet(self, ip_layer: Optional[IP]) -> None:
        if ip_layer is None:
            self._reassembler.process(None)
            self._process_out_packets()
            self._state = RTSPSessionState.DONE
            return

        if not isinstance(ip_layer.data, TCP):
            self.logger.error("Unexpected protocol")
            return

        tcp_layer = ip_layer.data

        # We care only about the packets from the server
        if tcp_layer.sport not in RTSP_PORTS:
            self.logger.error("Unexpected port")
            return

        if self.client_ip is None and self.server_ip is None:
            self.server_ip = inet_to_str(ip_layer.src)
            self.client_ip = inet_to_str(ip_layer.dst)

        if tcp_layer.flags & TH_FIN:
            self._reassembler.process(None)
            self._process_out_packets()
            self._state = RTSPSessionState.DONE
            return

        if not tcp_layer.data or (tcp_layer.flags & TH_URG and tcp_layer.urp == 0):
            return

        end = len(tcp_layer.data)
        if tcp_layer.flags & TH_URG:
            end = tcp_layer.urp

        payload = tcp_layer.data[:end]

        self._reassembler.process(payload, tcp_layer.seq)
        self._process_out_packets()

    def _process_out_packets(self) -> None:
        while True:
            if self.state != RTSPSessionState.PROCESSING_RTSP:
                break

            try:
                out_packet, skipped = self._reassembler.get_output_packet()
            except EmptyQueueException:
                break

            if out_packet is None:
                self._state = RTSPSessionState.DONE
                break

            if skipped:
                # If we got the SDP and all the transport headers we can say
                # that we're done
                if self.sdp is not None and len(get_sdp_medias(self.sdp)) == len(
                    self.transport_headers
                ):
                    self._state = RTSPSessionState.DONE
                    return

                self.logger.warning("Lost an RTSP packet; Trying to recover")
                self._buffer = b""

            self._buffer += out_packet
            self._parse_rtsp_response()

    def _parse_rtsp_response(self) -> None:
        try:
            rtsp_response = RTSPResponse(self._buffer)
            self._buffer = rtsp_response.data  # Left over data
        except NeedData as e:
            return
        except UnpackError:
            self.logger.warning("Failed to parse response; Trying to recover")
            self._buffer = b""
            return

        # DESCRIBE response (SDP)
        if (
            rtsp_response.body
            and int(rtsp_response.status) == 200
            and "content-type" in rtsp_response.headers
            and rtsp_response.headers["content-type"].casefold() == "application/sdp"
        ):
            self.sdp = sdp_transform.parse(rtsp_response.body.decode())

        # SETUP response
        elif "transport" in rtsp_response.headers and int(rtsp_response.status) == 200:
            self.transport_headers.append(
                RTSPTransportHeader.parse(rtsp_response.headers["transport"])
            )
            if self.sdp is not None and len(get_sdp_medias(self.sdp)) == len(
                self.transport_headers
            ):
                self._state = RTSPSessionState.DONE

    @staticmethod
    def _parse_interleaved_header(header: bytes) -> Tuple[int, int, int]:
        assert len(header) >= INTERLEAVED_HEADER_LEN
        magic = header[0]
        channel = header[1]
        length = int.from_bytes(header[2:4], byteorder="big")
        return magic, channel, length

    def _valid_interleaved_header(self, magic, channel, length) -> bool:
        if (
            magic != INTERLEAVED_HEADER_MAGIC
            or (
                channel not in self.control_channels
                and channel not in self.data_channels
            )
            or length < MIN_RTP_SIZE
            or length > MAX_RTP_SIZE
        ):
            return False
        return True

    def get_rtp(self) -> Iterator[RTPPacket]:
        if self.state != RTSPSessionState.PROCESSING_RTP:
            self._buffer = b""
            self._state = RTSPSessionState.PROCESSING_RTP

        for out_packet, skipped in self._reassembler.get_output_packets():
            if not out_packet:
                continue

            if skipped:
                magic, channel, length = self._parse_interleaved_header(self._buffer)
                if self._valid_interleaved_header(magic, channel, length):
                    payload = self._buffer[INTERLEAVED_HEADER_LEN:]
                    padding = b"\x00" * (length - len(payload))
                    self._buffer += padding
                else:
                    self._buffer = b""

                if INTERLEAVED_HEADER_MAGIC in out_packet:
                    self._buffer += out_packet[
                        out_packet.find(INTERLEAVED_HEADER_MAGIC) :
                    ]

                if not self._buffer:
                    continue

            else:
                self._buffer += out_packet

            while True:
                if len(self._buffer) < INTERLEAVED_HEADER_LEN:
                    break

                magic, channel, length = self._parse_interleaved_header(self._buffer)

                if not self._valid_interleaved_header(magic, channel, length):
                    next_magic_index = self._buffer[1:].find(INTERLEAVED_HEADER_MAGIC)
                    if next_magic_index < 0:
                        self._buffer = b""
                        break

                    self._buffer = self._buffer[next_magic_index + 1 :]
                elif len(self._buffer[INTERLEAVED_HEADER_LEN:]) < length:
                    break
                else:
                    if channel in self.data_channels:
                        rtp_packet = RTPPacket.from_dpkt(
                            RTP(
                                self._buffer[
                                    INTERLEAVED_HEADER_LEN : INTERLEAVED_HEADER_LEN
                                    + length
                                ]
                            )
                        )
                        yield rtp_packet

                    self._buffer = self._buffer[INTERLEAVED_HEADER_LEN + length :]
