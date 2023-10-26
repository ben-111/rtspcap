import argparse
import logging
from pyshark import FileCapture

from rtsp_decoder.parse_rtsp import RTSPDataExtractor
from rtsp_decoder.rtp_decoder import RTPDecoder
from rtsp_decoder.sdp_utils import get_sdp_media_from_track_id
from rtsp_decoder.sdp_utils import get_media_format_specific_config
from rtsp_decoder.sdp_utils import translate_sdp_to_av_codec

from typing import Dict

def main(input_path: str, output_path: str, debug: bool) -> None:
    logging_level = logging.INFO
    if debug:
        logging_level = logging.DEBUG

    logging.basicConfig(level=logging_level, format='[%(levelname)s] %(message)s')
    logger = logging.getLogger('RTSP Decoder')
    logger.debug(f'Running with arguments: {input_path=}, {output_path=}')
    rtsp_data = RTSPDataExtractor(input_path)
    with RTPDecoder(output_path) as rtp_decoder:
        for track_id, track in rtsp_data.tracks.items():
            sdp_media = get_sdp_media_from_track_id(rtsp_data.sdp, track_id)
            codec = translate_sdp_to_av_codec(sdp_media['rtp'][0]['codec'])
            rate = sdp_media['rtp'][0]['rate']
            config = get_media_format_specific_config(sdp_media)
            rtp_capture = FileCapture(input_path, display_filter=f'rtp and ip.src == {track.server_ip} and udp.srcport == {track.server_port} and udp.dstport == {track.client_port}')
            rtp_decoder.decode_stream(rtp_capture, config, codec, rate)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RTSP server from pcap')
    parser.add_argument('input', help='Path to pcap with RTSP and RTP data')
    parser.add_argument('output', help='Path to output file')
    parser.add_argument('--debug', action='store_true', help='Add debug prints')
    args = parser.parse_args()

    main(args.input, args.output, debug=args.debug)
