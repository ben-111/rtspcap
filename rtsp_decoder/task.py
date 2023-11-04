from enum import Enum

from pyshark.packet.packet import Packet

from typing import NamedTuple, Union


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


class TaskType(Enum):
    CREATE_DECODER = 0
    PROCESS_RTP_PACKET = 1


class CreateDecoderTaskBody(NamedTuple):
    ident: int
    sdp_media: dict


class ProcessRTPPacketTaskBody(NamedTuple):
    ident: int
    rtp_packet: RTPPacket


class Task(NamedTuple):
    ttype: TaskType
    body: Union[CreateDecoderTaskBody, ProcessRTPPacketTaskBody]
