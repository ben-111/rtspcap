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
    def from_dpkt(cls, packet: RTP) -> "RTPPacket":
        return cls(
            marker=bool(packet.m),
            payload_type=packet.pt,
            seq=packet.seq,
            timestamp=packet.ts,
            ssrc=packet.ssrc,
            payload=packet.data,
        )
