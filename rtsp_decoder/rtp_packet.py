from pyshark.packet.packet import Packet
from dpkt.rtp import RTP

from typing import NamedTuple


class RTPPacket(NamedTuple):
    marker: bool
    payload_type: int
    seq: int
    timestamp: int
    ssrc: int
    payload: bytes

    @classmethod
    def from_pyshark(cls, packet: Packet) -> "RTPPacket":
        assert "RTP" in packet
        rtp_layer = packet["RTP"]
        return cls(
            marker=bool(rtp_layer.marker),
            payload_type=int(rtp_layer.p_type),
            seq=int(rtp_layer.seq),
            timestamp=int(rtp_layer.timestamp),
            ssrc=int(rtp_layer.ssrc, 16),
            payload=bytes.fromhex(rtp_layer.payload.raw_value),
        )

    @classmethod
    def from_dpkt(cls, packet: RTP) -> "RTPPacket":
        return cls(
            marker=bool(packet.m),
            payload_type=packet.pt,
            seq=packet.seq,
            timestamp=packet.ts,
            ssrc=packet.ssrc,
            payload=packet.data,
        )
