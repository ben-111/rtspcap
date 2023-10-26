from typing import Dict

# To get this mapping we look at all the `RTPDynamicProtocolHandler`s in the ffmpeg library
SDP_CODEC_TO_AV_CODEC = {
    'mp4v-es': 'mpeg4',
    'mpeg4-generic': 'aac',
    'h263-1998': 'h263',
    'h263-2000': 'h263',
    'ilbc': 'ilbc',
    'amr': 'amr_nb',
    'amr-wb': 'amr_wb',
    'ac3': 'ac3',
    'dv': 'dvvideo',
    'mp4a-latm': 'aac',
    'h261': 'h261',
    'vc2': 'dirac',
    'x-purevoice': 'qcelp',
    'vp8': 'vp8',
    'h265': 'hevc',
    'jpeg': 'mjpeg',
    'theora': 'theora',
    'vorbis': 'vorbis',
    'mpa-robust': 'mp3adu',
    'h264': 'h264',
    'vp9': 'vp9',
}

def translate_sdp_to_av_codec(codec_name: str) -> str:
    normalized_codec_name = codec_name.casefold()
    if normalized_codec_name not in SDP_CODEC_TO_AV_CODEC:
        raise ValueError(f'{codec_name} not implemented')

    return SDP_CODEC_TO_AV_CODEC[normalized_codec_name]

def get_sdp_media_from_track_id(sdp_data, track_id: str):
    for media in sdp_data['media']:
        if media['control'] == track_id:
            return media
    raise KeyError('No such track ID in SDP provided')

def get_media_format_specific_config(sdp_media) -> Dict[str, str]:
    config_dict: Dict[str, str] = dict()
    if 'fmtp' in sdp_media and len(sdp_media['fmtp']) > 0:
        fmtp_data = sdp_media['fmtp'][0]
        if 'config' in fmtp_data:
            config = fmtp_data['config']
            parameters = config.split('; ')
            for parameter in parameters:
                key, value = parameter.split('=')
                config_dict[key] = value
    if 'type' in sdp_media and sdp_media['type'] == 'audio':
        if 'rtp' in sdp_media and len(sdp_media['rtp']) > 0 and 'encoding' in sdp_media['rtp'][0]:
            config_dict['channels'] = sdp_media['rtp'][0]['encoding']
    return config_dict
