from av.codec import CodecContext
import logging

from rtsp_decoder.codecs.stream_codec import StreamCodec

from typing import Dict, Optional, List


logger = logging.getLogger(__name__)


def get_sdp_medias(sdp: dict) -> List[dict]:
    assert "media" in sdp
    return sdp["media"]


def get_payload_type_from_sdp_media(sdp_media: dict) -> int:
    assert "payloads" in sdp_media and isinstance(sdp_media["payloads"], int)
    return sdp_media["payloads"]


def _get_codec_name_from_sdp_media(sdp_media: dict) -> str:
    assert "rtp" in sdp_media and sdp_media["rtp"] and "codec" in sdp_media["rtp"][0]
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
    except ValueError as e:
        logger.warning(str(e))

    return stream_codec
