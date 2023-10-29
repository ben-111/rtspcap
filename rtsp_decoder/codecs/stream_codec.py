from av.codec import CodecContext
from av.packet import Packet as AVPacket
from av.frame import Frame

from pyshark.packet.packet import Packet

from rtsp_decoder.codecs.codec_base import CodecBase
from rtsp_decoder.codecs.h264 import CodecH264
from rtsp_decoder.codecs.mp4v_es import CodecMP4V_ES
from rtsp_decoder.codecs.mpeg4_generic import CodecMPEG4_GENERIC

from typing import List, Dict, Optional


class StreamCodec:
    _CODEC_MAP: Dict[str, CodecBase] = {
        "h264": CodecH264,
        "mp4v-es": CodecMP4V_ES,
        # "mpeg4-generic": CodecMPEG4_GENERIC,
    }

    def __init__(self, codec_name: str, sdp_media: dict):
        codec_name = codec_name.casefold()
        if codec_name not in self._CODEC_MAP:
            raise KeyError(f"Codec {codec_name} not implemented")

        self.codec_name = codec_name
        self._codec = self._CODEC_MAP[self.codec_name]
        self._codec_ctx, self._payload_context = self._codec.get_codec_context(
            sdp_media
        )
        self.codec_type = self._codec_ctx.type

    def handle_packet(
        self,
        packet: Packet,
    ) -> List[AVPacket]:
        return self._codec.handle_packet(self._codec_ctx, packet, self._payload_context)

    def decode(self, av_packet: Optional[AVPacket] = None) -> List[Frame]:
        return self._codec_ctx.decode(av_packet)
