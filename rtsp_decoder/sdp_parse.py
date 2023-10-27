from av.codec import CodecContext

from typing import Dict, Optional

import logging


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


def _parse_fmtp(sdp_media: dict) -> Dict[str, str]:
    fmtp_config: Dict[str, str] = dict()
    if "fmtp" in sdp_media and len(sdp_media["fmtp"]) > 0:
        fmtp_data = sdp_media["fmtp"][0]
        if "config" in fmtp_data:
            config = fmtp_data["config"]
            parameters = config.split("; ")
            for parameter in parameters:
                key, value = parameter.split("=", 1)
                fmtp_config[key] = value
    return fmtp_config


def _get_mpeg4_codec_context(sdp_media: dict) -> CodecContext:
    fmtp = _parse_fmtp(sdp_media)
    if "config" not in fmtp:
        raise ValueError("Expected config in fmtp of mpeg4")

    codec_ctx = CodecContext.create("mpeg4", "r")
    codec_ctx.extradata = bytes.fromhex(fmtp["config"])
    return codec_ctx


_CODEC_SDP_PARSERS = {
    "mpeg4": _get_mpeg4_codec_context,
}


def get_codec_context(sdp: dict, track_id: str) -> Optional[CodecContext]:
    sdp_media = _get_sdp_media_from_track_id(sdp, track_id)
    codec = _get_codec_from_sdp_media(sdp_media)
    if codec not in _CODEC_SDP_PARSERS:
        logger.error(f"Got unsupported codec: {codec}")
        return

    get_specific_codec_context = _CODEC_SDP_PARSERS[codec]
    return get_specific_codec_context(sdp_media)
