from enum import Enum

from rtsp_decoder.rtp_packet import RTPPacket

from typing import NamedTuple, Union


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
