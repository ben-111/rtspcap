import av
from pyshark import FileCapture
from pyshark.packet.packet import Packet

from typing import Dict, Optional

import logging


class RTPDecoder:
    MAX_OUT_OF_ORDER_PACKETS = 50

    def __init__(self, output_path: str):
        self.container = av.open(output_path, "w")
        self.logger = logging.getLogger(__name__)

    def decode_stream(
        self, rtp_capture: FileCapture, config: Dict[str, str], codec: str, rate: int
    ):
        """Assume rtp_capture is filtered so that all RTP packets we see are from the same stream"""
        self.logger.info(f"Decoding Stream with codec: {codec}")
        input_codec_ctx = av.codec.CodecContext.create(codec, "r")
        if input_codec_ctx.type == "video":
            stream = self.container.add_stream("h264", rate=30)
            if "config" in config:
                input_codec_ctx.extradata = bytes.fromhex(config["config"])
        # TODO: support audio
        # elif input_codec_ctx.type == 'audio':
        #     stream = self.container.add_stream('aac')
        #     input_codec_ctx.rate = rate
        #     input_codec_ctx.channels = config['channels']
        else:
            self.logger.warning(
                f"Unsupported stream type: {input_codec_ctx.type}, with codec: {codec}, skipping"
            )
            return

        out_of_order_packets: Dict[int, Packet] = dict()
        expected_seq = None
        rtp_stream = filter(lambda x: "RTP" in x, rtp_capture)
        try:
            expected_seq = int(next(rtp_stream)["RTP"].seq) + 1
            self.logger.debug(f"First seq is {expected_seq-1}")
        except StopIteration:
            raise ValueError("RTP stream not found")

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

                continue
            else:
                expected_seq += 1

            self.logger.debug(f"Processing RTP packet with seq {seq}")
            chunk = bytes.fromhex(packet["RTP"].payload.raw_value)
            out_packets = input_codec_ctx.parse(chunk)
            self.logger.debug(f'Parsed {len(out_packets)} packets from chunk of size {len(chunk)}')
            for out_packet in out_packets:
                frames = input_codec_ctx.decode(out_packet)
                self.logger.debug(f'Decoded {len(frames)} frames')
                for frame in frames:
                    encoded_packet = stream.encode(frame)
                    self.container.mux(encoded_packet)

        # Flush the encoder
        out_packet = stream.encode(None)
        self.container.mux(out_packet)

    def close(self):
        self.container.close()

    def __enter__(self) -> "RTPDecoder":
        return self

    def __exit__(self, exception_type, exception_value, exception_trace):
        self.close()
