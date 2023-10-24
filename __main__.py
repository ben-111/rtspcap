import argparse
from rtsp_decoder.parse_rstp import RTSPDataExtractor

def main(pcap_path: str) -> None:
    rtsp_data = RTSPDataExtractor(pcap_path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RTSP server from pcap')
    parser.add_argument('path', help='Path to pcap with RTSP and RTP data')
    args = parser.parse_args()

    main(args.path)
