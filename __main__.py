import argparse
from pyshark import FileCapture

from rtsp_decoder.parse_rtsp import RTSPDataExtractor
from rtsp_decoder.sdp_to_av import translate_sdp_to_av_codec
from rtsp_decoder.rtp_decoder import RTPDecoder

from typing import Dict

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

def main(input_path: str, output_path: str) -> None:
    rtsp_data = RTSPDataExtractor(input_path)
    rtp_decoder = RTPDecoder(output_path)
    for track_id, track in rtsp_data.tracks.items():
        sdp_media = get_sdp_media_from_track_id(rtsp_data.sdp, track_id)
        codec = translate_sdp_to_av_codec(sdp_media['rtp'][0]['codec'])
        rate = sdp_media['rtp'][0]['rate']
        config = get_media_format_specific_config(sdp_media)
        rtp_capture = FileCapture(input_path, display_filter=f'rtp and ip.src == {track.server_ip} and udp.srcport == {track.server_port} and udp.dstport == {track.client_port}')
        rtp_decoder.decode_stream(rtp_capture, config, codec, rate)
    rtp_decoder.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RTSP server from pcap')
    parser.add_argument('input', help='Path to pcap with RTSP and RTP data')
    parser.add_argument('output', help='Path to output file')
    args = parser.parse_args()

    main(args.input, args.output)
