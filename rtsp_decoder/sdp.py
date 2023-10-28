from av.codec import CodecContext
import logging

from rtsp_decoder.codecs.stream_codec import StreamCodec

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


def _get_codec_name_from_sdp_media(sdp_media: dict) -> str:
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


def get_stream_codec(sdp: dict, track_id: str) -> Optional[StreamCodec]:
    sdp_media = _get_sdp_media_from_track_id(sdp, track_id)
    codec_name = _get_codec_name_from_sdp_media(sdp_media)
    stream_codec = None

    try:
        stream_codec = StreamCodec(codec_name, sdp_media)
    except KeyError as e:
        logger.warning(str(e))

    return stream_codec
