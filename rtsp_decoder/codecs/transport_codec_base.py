from abc import ABC, abstractmethod

from av.packet import Packet as AVPacket
from av.frame import Frame

from pyshark.packet.packet import Packet

from typing import List, Optional


class TransportCodecBase(ABC):
    @abstractmethod
    def __init__(self, codec_name: str, sdp_media: dict):
        ...

    @property
    @abstractmethod
    def codec_name(self) -> str:
        ...

    @property
    @abstractmethod
    def codec_type(self) -> str:
        ...

    @abstractmethod
    def handle_packet(
        self,
        packet: Packet,
    ) -> List[AVPacket]:
        ...

    @abstractmethod
    def decode(self, av_packet: Optional[AVPacket] = None) -> List[Frame]:
        ...
