from av.codec import CodecContext

from rtsp_decoder.codecs.sdp_common import CodecSDPParser, parse_fmtp


class MPEG4SDPParser(CodecSDPParser):
    @staticmethod
    def get_codec_context(sdp_media: dict) -> CodecContext:
        fmtp = parse_fmtp(sdp_media)
        assert "config" in fmtp, "Expected config in fmtp of mpeg4"

        codec_ctx = CodecContext.create("mpeg4", "r")

        # TODO: check if there is more to do
        codec_ctx.extradata = bytes.fromhex(fmtp["config"])
        return codec_ctx
