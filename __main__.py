import argparse
from rtsp_decoder.simple_rtsp_server import SimpleRTSPServer

from pyshark import FileCapture


def extract_rtsp_data(pcap_path: str):
    cap = FileCapture(pcap_path, display_filter=f'rtsp')
    first_rtsp = cap.next()
    tcp_stream = first_rtsp.tcp.stream
    cap = FileCapture(pcap_path, display_filter=f'rtsp and tcp.stream == {tcp_stream}')
    while True:
        try:
            request = cap.next()
            response = cap.next()
            ...
        except StopIteration:
            break

def main(pcap_path: str) -> None:
    extract_rtsp_data(pcap_path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RTSP server from pcap')
    parser.add_argument('path', help='Path to pcap with RTSP and RTP data')
    args = parser.parse_args()

    main(args.path)
