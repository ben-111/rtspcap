"""
To get this mapping we look at all the `RTPDynamicProtocolHandler`s in the ffmpeg library
"""

SDP_CODEC_TO_AV_CODEC = {
    'mp4v-es': 'mpeg4',
    'mpeg4-generic': 'aac',
}

def translate_sdp_to_av_codec(codec_name: str) -> str:
    normalized_codec_name = codec_name.casefold()
    if normalized_codec_name not in SDP_CODEC_TO_AV_CODEC:
        raise ValueError(f'{codec_name} not implemented')

    return SDP_CODEC_TO_AV_CODEC[normalized_codec_name]
