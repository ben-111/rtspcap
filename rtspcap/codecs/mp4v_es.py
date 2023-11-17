from av.codec import CodecContext

from rtspcap.codecs.codec_base import CodecBase

from typing import Tuple, Any


class CodecMP4V_ES(CodecBase):
    AV_CODEC_NAME = "mpeg4"

    @classmethod
    def get_codec_context(cls, sdp_media: dict) -> Tuple[CodecContext, Any]:
        fmtp = cls._parse_fmtp(sdp_media)

        codec_ctx = CodecContext.create(cls.AV_CODEC_NAME, "r")
        if "config" in fmtp:
            codec_ctx.extradata = bytes.fromhex(fmtp["config"])

        return codec_ctx, None
