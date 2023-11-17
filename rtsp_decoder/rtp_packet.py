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
        data = packet.data
        if packet.p:
            padding_length = data[-1]
            data = data[:-padding_length]

        return cls(
            marker=bool(packet.m),
            payload_type=packet.pt,
            seq=packet.seq,
            timestamp=packet.ts,
            ssrc=packet.ssrc,
            payload=data,
        )
