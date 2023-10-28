from abc import ABC, abstractmethod

from av.codec import CodecContext
from av.packet import Packet as AVPacket

from pyshark.packet.packet import Packet

from typing import List


class CodecRTPDecoder(ABC):
    @staticmethod
    @abstractmethod
    def handle_packet(
        codec_ctx: CodecContext,
        packet: Packet,
    ) -> List[AVPacket]:
        ...
