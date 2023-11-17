from dpkt.http import Request, Response

# From RFC 2326 Section 10
PROTO = "RTSP"
METHODS = dict.fromkeys(
    (
        "OPTIONS",
        "DESCRIBE",
        "ANNOUNCE",
        "SETUP",
        "PLAY",
        "PAUSE",
        "TEARDOWN",
        "GET_PARAMETER",
        "SET_PARAMETER",
        "REDIRECT",
        "RECORD",
    )
)


# This is a bit of a hack which depends on the internal
# implementation of Request and Response, but it works
class RTSPRequest(Request):
    _Request__proto = PROTO
    _Request__methods = METHODS


class RTSPResponse(Response):
    _Response__proto = PROTO
    _Response__methods = METHODS
