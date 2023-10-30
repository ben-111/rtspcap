from fractions import Fraction
import logging
from av.codec import CodecContext

from rtsp_decoder.codecs.stream_codec import StreamCodec

from typing import Dict, Optional, Any


logger = logging.getLogger(__name__)


def _get_codec_name_from_sdp_media(sdp_media: dict) -> str:
    return sdp_media["rtp"][0]["codec"]


def _get_time_base_from_sdp_media(sdp_media: dict) -> Fraction:
    clock_rate_in_hz = sdp_media["rtp"][0]["rate"]
    return Fraction(1, clock_rate_in_hz)


def _get_sdp_media_from_track_id(sdp_data, track_id: str):
    for media in sdp_data["media"]:
        if media["control"] == track_id:
            return media
    raise KeyError("No such track ID in SDP provided")


def get_stream_codec(
    transport_protocol: str, sdp: dict, track_id: str, transport_specific_data: Any
) -> Optional[StreamCodec]:
    sdp_media = _get_sdp_media_from_track_id(sdp, track_id)
    codec_name = _get_codec_name_from_sdp_media(sdp_media)
    time_base = _get_time_base_from_sdp_media(sdp_media)
    stream_codec = None

    try:
        stream_codec = StreamCodec(
            transport_protocol,
            codec_name,
            time_base,
            sdp_media,
            transport_specific_data,
        )
    except ValueError as e:
        logger.warning(str(e))

    return stream_codec
