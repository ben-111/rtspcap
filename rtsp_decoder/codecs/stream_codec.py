from av.codec import CodecContext
from av.packet import Packet as AVPacket
from av.frame import Frame

from pyshark.packet.packet import Packet

from rtsp_decoder.codecs.transport_codec_base import TransportCodecBase
from rtsp_decoder.codecs.rtp_codec import RTPCodec

from typing import List, Dict, Optional


class StreamCodec:
    _TRANSPORT_CODEC_MAP: Dict[str, TransportCodecBase] = {
        "rtp/avp": RTPCodec,
        "rtp/avp/udp": RTPCodec,
        "rtp/avp/tcp": RTPCodec,
    }

    def __init__(self, transport_protocol: str, codec_name: str, sdp_media: dict):
        transport_proto = transport_protocol.casefold()
        if transport_proto not in self._TRANSPORT_CODEC_MAP:
            raise ValueError(f"Codecs for transport {transport_proto} not implemented")

        self.transport_proto = transport_proto
        self._transport_codec = self._TRANSPORT_CODEC_MAP[self.transport_proto](
            codec_name, sdp_media
        )
        self.codec_name = self._transport_codec.codec_name
        self.codec_type = self._transport_codec.codec_type

    def handle_packet(
        self,
        packet: Packet,
    ) -> List[AVPacket]:
        return self._transport_codec.handle_packet(packet)

    def decode(self, av_packet: Optional[AVPacket] = None) -> List[Frame]:
        return self._transport_codec.decode(av_packet)
