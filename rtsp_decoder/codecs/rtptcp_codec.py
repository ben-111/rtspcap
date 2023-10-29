from av.packet import Packet as AVPacket
from av.frame import Frame
from pyshark.packet.packet import Packet

from rtsp_decoder.codecs.transport_codec_base import TransportCodecBase

from typing import List, Optional


class RTPOverTCPCodec(TransportCodecBase):
    def __init__(self, codec_name: str, sdp_media: dict):
        self._codec_name = codec_name

    @property
    def codec_name(self) -> str:
        return self._codec_name

    @property
    def codec_type(self) -> str:
        ...

    def handle_packet(
        self,
        packet: Packet,
    ) -> List[AVPacket]:
        ...

    def decode(self, av_packet: Optional[AVPacket] = None) -> List[Frame]:
        ...
