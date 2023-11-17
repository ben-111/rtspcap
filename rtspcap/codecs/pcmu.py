from av.codec import CodecContext
from av.packet import Packet as AVPacket

from rtspcap.codecs.codec_base import CodecBase
from rtspcap.rtp_packet import RTPPacket

from typing import Tuple, Any, List, Optional


class CodecPCMU(CodecBase):
    AV_CODEC_NAME = "pcm_mulaw"

    @classmethod
    def get_codec_context(cls, sdp_media: dict) -> Tuple[CodecContext, Any]:
        rtp_data = sdp_media["rtp"][0]
        rate = rtp_data["rate"]

        codec_ctx = CodecContext.create(cls.AV_CODEC_NAME, mode="r")
        codec_ctx.rate = rate
        codec_ctx.layout = int(rtp_data["encoding"]) if "encoding" in rtp_data else 1
        return codec_ctx, None

    @classmethod
    def handle_packet(
        cls,
        codec_ctx: CodecContext,
        packet: Optional[RTPPacket],
        _: Any,
    ) -> List[AVPacket]:
        if packet is None:
            return [AVPacket()]

        return [AVPacket(packet.payload)]
