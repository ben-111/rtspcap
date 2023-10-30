from av.codec import CodecContext

from rtsp_decoder.rtsp import RTPInfo
from rtsp_decoder.codecs.rtp_codecs.rtp_codec_base import RTPCodecBase

from typing import Tuple, Any, Optional


class RTPCodecMP4V_ES(RTPCodecBase):
    AV_CODEC_NAME = "mpeg4"

    @classmethod
    def get_codec_context(
        cls, sdp_media: dict, rtp_info: Optional[RTPInfo]
    ) -> Tuple[CodecContext, Any]:
        fmtp = RTPCodecBase._parse_fmtp(sdp_media)

        codec_ctx = CodecContext.create(cls.AV_CODEC_NAME, "r")
        if "config" in fmtp:
            codec_ctx.extradata = bytes.fromhex(fmtp["config"])
        else:
            self.logger.error("Expected config attribute in fmtp")

        return codec_ctx, None
