import av
from pyshark import FileCapture
from pyshark.packet.packet import Packet

from typing import Dict, Optional

class RTPDecoder:
    def __init__(self, output_path: str):
        self.container = av.open(output_path, 'w')

    def decode_stream(self, rtp_capture: FileCapture, config: Optional[Dict[str, str]], codec: str, rate: int):
        """Assume rtp_capture is filtered so that all RTP packets we see are from the same stream"""
        out_of_order_packets: Dict[int, Packet] = dict()
        expected_seq = None
        while True:
            packet = rtp_capture.next()
            if 'RTP' in packet:
                expected_seq = int(packet['RTP'].seq) + 1
                break

        assert expected_seq is not None, "RTP stream not found"
        
        input_codec_ctx = av.codec.CodecContext.create(codec, 'r')
        if input_codec_ctx.type == 'video':
            stream = self.container.add_stream('h264', rate=30)
        elif input_codec_ctx.type == 'audio':
            stream = self.container.add_stream('aac')
        else:
            raise ValueError('Unsupported stream type')
        
        if config is not None:
            input_codec_ctx.options = config
            if 'config' in config:
                input_codec_ctx.parse(bytes.fromhex(config['config']))

        for packet in filter(lambda x: 'RTP' in x, rtp_capture):
            seq = int(packet['RTP'].seq)
            if seq != expected_seq:
                if seq in out_of_order_packets:
                    packet = out_of_order_packets.pop(seq)
                else:
                    out_of_order_packets[seq] = packet
                    continue

            chunk = bytes.fromhex(packet['RTP'].payload.raw_value)
            out_packets = input_codec_ctx.parse(chunk)
            for out_packet in out_packets:
                frames = input_codec_ctx.decode(out_packet)
                for frame in frames:
                    encoded_packet = stream.encode(frame)
                    self.container.mux(encoded_packet)

            expected_seq += 1
        
        # Flush the encoder
        out_packet = stream.encode(None)
        self.container.mux(out_packet)

    def close(self):
        self.container.close()
