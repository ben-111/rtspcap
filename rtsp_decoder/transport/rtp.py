from pyshark import FileCapture
from pyshark.packet.packet import Packet

from rtsp_decoder.transport.transport_base import TransportBase
from rtsp_decoder.rtsp import TransportInformation

from typing import Dict, Iterator


class RTPDecoder(TransportBase):
    MAX_OUT_OF_ORDER_PACKETS = 50

    def __init__(self, transport_info: TransportInformation, output_path: str):
        super().__init__(transport_info, output_path)
        self._display_filter = self._build_display_filter(transport_info)

    def _build_display_filter(self, transport_info: TransportInformation) -> str:
        transport_header = transport_info.transport_header
        server_ip = transport_info.server_ip
        client_ip = transport_info.client_ip
        client_port, _ = transport_header.options["client_port"].split("-", 1)
        server_port, _ = transport_header.options["server_port"].split("-", 1)

        display_filter = "rtp and "
        display_filter += f"ip.src == {server_ip} and "
        display_filter += f"ip.dst == {client_ip} and "
        display_filter += f"udp.srcport == {server_port} and "
        display_filter += f"udp.dstport == {client_port}"
        return display_filter

    def _iterate_packets(self, pcap_path: str) -> Iterator[Packet]:
        rtp_capture = FileCapture(pcap_path, display_filter=self._display_filter)
        out_of_order_packets: Dict[int, Packet] = dict()
        expected_seq = None
        try:
            while True:
                packet = rtp_capture.next()
                if "RTP" in packet:
                    expected_seq = int(packet["RTP"].seq)
                    self.logger.debug(f"First seq is {expected_seq}")
                    break
        except StopIteration:
            raise ValueError("RTP stream not found")

        rtp_capture.reset()
        rtp_stream = filter(lambda x: "RTP" in x, rtp_capture)
        while True:
            try:
                if expected_seq in out_of_order_packets:
                    packet = out_of_order_packets.pop(expected_seq)
                else:
                    packet = next(rtp_stream)
            except StopIteration:
                if out_of_order_packets:
                    earliest_packet = min(out_of_order_packets.keys())
                    packet = out_of_order_packets.pop(earliest_packet)
                    expected_seq = int(packet["RTP"].seq)
                    self.logger.debug(
                        f"Out of order packet with seq {expected_seq} found after the end of the pcap file; Appending to the end"
                    )
                else:
                    break

            seq = int(packet["RTP"].seq)
            if seq != expected_seq:
                out_of_order_packets[seq] = packet
                if len(out_of_order_packets) > self.MAX_OUT_OF_ORDER_PACKETS:
                    self.logger.debug(
                        f"Could not find packet with sequence number {expected_seq}; Likely packet loss"
                    )
                    expected_seq += 1
                    expected_seq %= 1 << 16

                continue
            else:
                expected_seq += 1
                expected_seq %= 1 << 16

            self.logger.debug(f"Processing RTP packet with seq {seq}")
            yield packet

        # Flush the decoder
        yield None

    def close(self):
        self.container.close()
