import logging

from av.packet import Packet as AVPacket
from av.frame import Frame

from rtspcap.rtp_packet import RTPPacket

from rtspcap.codecs.codec_base import CodecBase
from rtspcap.codecs.h264 import CodecH264
from rtspcap.codecs.h265 import CodecH265
from rtspcap.codecs.mp4v_es import CodecMP4V_ES
from rtspcap.codecs.mpeg4_generic import CodecMPEG4_GENERIC
from rtspcap.codecs.pcma import CodecPCMA
from rtspcap.codecs.pcmu import CodecPCMU

from typing import List, Dict, Optional


class RTPCodec:
    _CODEC_MAP: Dict[str, CodecBase] = {
        "h264": CodecH264,
        "h265": CodecH265,
        "mp4v-es": CodecMP4V_ES,
        "mpeg4-generic": CodecMPEG4_GENERIC,
        "pcma": CodecPCMA,
        "pcmu": CodecPCMU,
    }

    def __init__(self, codec_name: str, sdp_media: dict, fast: bool = False):
        self.logger = logging.getLogger(__name__)
        codec_name = codec_name.casefold()
        if codec_name not in self._CODEC_MAP:
            raise ValueError(f"Codec {codec_name} not implemented")

        self._codec_name = codec_name
        self._codec = self._CODEC_MAP[self.codec_name]
        self._codec_ctx, self._payload_context = self._codec.get_codec_context(
            sdp_media
        )
        self._codec_type = self._codec_ctx.type

        if fast:
            self._codec_ctx.thread_type = "AUTO"

    @property
    def codec_name(self) -> str:
        return self._codec_name

    @property
    def av_codec_name(self) -> str:
        return self._codec.AV_CODEC_NAME

    @property
    def codec_type(self) -> str:
        return self._codec_type

    @property
    def ready(self) -> bool:
        if self.codec_type == "video":
            return self._codec_ctx.width != 0
        else:
            return True

    @property
    def rate(self) -> int:
        return self._codec_ctx.rate

    @property
    def width(self) -> int:
        return self._codec_ctx.width

    @property
    def height(self) -> int:
        return self._codec_ctx.height

    def handle_packet(
        self,
        packet: RTPPacket,
    ) -> List[AVPacket]:
        return self._codec.handle_packet(self._codec_ctx, packet, self._payload_context)

    def decode(self, av_packet: Optional[AVPacket] = None) -> List[Frame]:
        out_frames = []
        try:
            out_frames = self._codec_ctx.decode(av_packet)
        except Exception as e:
            self.logger.debug(f"Failed decoding with {e}")
        finally:
            return out_frames
