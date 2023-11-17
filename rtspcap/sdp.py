from typing import List


def get_sdp_medias(sdp: dict) -> List[dict]:
    assert "media" in sdp
    return sdp["media"]


def get_payload_type_from_sdp_media(sdp_media: dict) -> int:
    assert "payloads" in sdp_media and isinstance(sdp_media["payloads"], int)
    return sdp_media["payloads"]


def get_codec_name_from_sdp_media(sdp_media: dict) -> str:
    assert "rtp" in sdp_media and sdp_media["rtp"] and "codec" in sdp_media["rtp"][0]
    return sdp_media["rtp"][0]["codec"]
