from av.codec import CodecContext
from av.packet import Packet as AVPacket
from av.frame import Frame

from pyshark.packet.packet import Packet

from rtsp_decoder.rtsp import RTPInfo
from rtsp_decoder.codecs.transport_codec_base import TransportCodecBase
from rtsp_decoder.codecs.rtp_codecs.rtp_codec_base import RTPCodecBase
from rtsp_decoder.codecs.rtp_codecs.h264 import RTPCodecH264
from rtsp_decoder.codecs.rtp_codecs.mp4v_es import RTPCodecMP4V_ES
from rtsp_decoder.codecs.rtp_codecs.mpeg4_generic import RTPCodecMPEG4_GENERIC

from typing import List, Dict, Optional, Any


class RTPCodec(TransportCodecBase):
    _CODEC_MAP: Dict[str, RTPCodecBase] = {
        "h264": RTPCodecH264,
        "mp4v-es": RTPCodecMP4V_ES,
        # "mpeg4-generic": RTPCodecMPEG4_GENERIC,
    }

    def __init__(self, codec_name: str, sdp_media: dict, transport_specific_data: Any):
        codec_name = codec_name.casefold()
        if codec_name not in self._CODEC_MAP:
            raise ValueError(f"Codec {codec_name} not implemented")

        rtp_info = transport_specific_data
        self._codec_name = codec_name
        self._codec = self._CODEC_MAP[self.codec_name]
        self._codec_ctx, self._payload_context = self._codec.get_codec_context(
            sdp_media, rtp_info
        )
        self._codec_type = self._codec_ctx.type

    @property
    def codec_name(self) -> str:
        return self._codec_name

    @property
    def codec_type(self) -> str:
        return self._codec_type

    def handle_packet(
        self,
        packet: Packet,
    ) -> List[AVPacket]:
        return self._codec.handle_packet(self._codec_ctx, packet, self._payload_context)

    def decode(self, av_packet: Optional[AVPacket] = None) -> List[Frame]:
        return self._codec_ctx.decode(av_packet)
