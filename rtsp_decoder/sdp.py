from av.codec import CodecContext
import logging

from rtsp_decoder.codecs.stream_codec import StreamCodec

from typing import Dict, Optional


logger = logging.getLogger(__name__)


def _get_codec_name_from_sdp_media(sdp_media: dict) -> str:
    return sdp_media["rtp"][0]["codec"]


def _get_sdp_media_from_track_id(sdp_data, track_id: str):
    for media in sdp_data["media"]:
        if media["control"] == track_id:
            return media
    raise KeyError("No such track ID in SDP provided")


def get_stream_codec(
    transport_protocol: str, sdp: dict, track_id: str
) -> Optional[StreamCodec]:
    sdp_media = _get_sdp_media_from_track_id(sdp, track_id)
    codec_name = _get_codec_name_from_sdp_media(sdp_media)
    stream_codec = None

    try:
        stream_codec = StreamCodec(transport_protocol, codec_name, sdp_media)
    except KeyError as e:
        logger.warning(str(e))

    return stream_codec
