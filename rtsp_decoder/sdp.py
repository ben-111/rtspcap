from av.codec import CodecContext
import logging

from rtsp_decoder.codecs.sdp_common import CodecSDPParser
from rtsp_decoder.codecs.mpeg4 import MPEG4SDPParser
from rtsp_decoder.codecs.h264 import H264SDPParser

from typing import Dict, Optional


logger = logging.getLogger(__name__)

# To get this mapping we look at all the `RTPDynamicProtocolHandler`s in the ffmpeg library
_SDP_CODEC_TO_AV_CODEC = {
    "mp4v-es": "mpeg4",
    "mpeg4-generic": "aac",
    "h263-1998": "h263",
    "h263-2000": "h263",
    "ilbc": "ilbc",
    "amr": "amr_nb",
    "amr-wb": "amr_wb",
    "ac3": "ac3",
    "dv": "dvvideo",
    "mp4a-latm": "aac",
    "h261": "h261",
    "vc2": "dirac",
    "x-purevoice": "qcelp",
    "vp8": "vp8",
    "h265": "hevc",
    "jpeg": "mjpeg",
    "theora": "theora",
    "vorbis": "vorbis",
    "mpa-robust": "mp3adu",
    "h264": "h264",
    "vp9": "vp9",
}


def _get_codec_from_sdp_media(sdp_media: dict) -> str:
    codec_name = sdp_media["rtp"][0]["codec"]
    normalized_codec_name = codec_name.casefold()
    if normalized_codec_name not in _SDP_CODEC_TO_AV_CODEC:
        raise ValueError(f"{codec_name} not implemented")

    return _SDP_CODEC_TO_AV_CODEC[normalized_codec_name]


def _get_sdp_media_from_track_id(sdp_data, track_id: str):
    for media in sdp_data["media"]:
        if media["control"] == track_id:
            return media
    raise KeyError("No such track ID in SDP provided")


_CODEC_SDP_PARSERS: Dict[str, CodecSDPParser] = {
    "mpeg4": MPEG4SDPParser,
    "h264": H264SDPParser,
}


def get_codec_context(sdp: dict, track_id: str) -> Optional[CodecContext]:
    sdp_media = _get_sdp_media_from_track_id(sdp, track_id)
    codec = _get_codec_from_sdp_media(sdp_media)
    if codec not in _CODEC_SDP_PARSERS:
        logger.warning(f"Got unsupported codec: {codec}")
        return

    codec_sdp_parser = _CODEC_SDP_PARSERS[codec]
    return codec_sdp_parser.get_codec_context(sdp_media)
