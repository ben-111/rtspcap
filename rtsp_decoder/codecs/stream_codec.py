from av.codec import CodecContext
from av.packet import Packet as AVPacket

from pyshark.packet.packet import Packet

from rtsp_decoder.codecs.codec_base import CodecBase
from rtsp_decoder.codecs.h264 import CodecH264
from rtsp_decoder.codecs.mpeg4 import CodecMPEG4

from typing import List, Dict


class StreamCodec:
    _CODEC_MAP: Dict[str, CodecBase] = {
        "h264": CodecH264,
        "mpeg4": CodecMPEG4,
    }

    def __init__(self, codec_name: str, sdp_media: dict):
        if codec_name not in self._CODEC_MAP:
            raise KeyError(f"Codec {codec_name} not implemented")

        self._codec = self._CODEC_MAP[codec_name]
        self.codec_ctx = self._codec.get_codec_context(sdp_media)

    def handle_packet(
        self,
        packet: Packet,
    ) -> List[AVPacket]:
        return self._codec.handle_packet(self.codec_ctx, packet)
