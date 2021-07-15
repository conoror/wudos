# Match to ~m HEAD & ~u msdownload with a response that includes
# the Content-Length header. Then zero that value

from mitmproxy import ctx

class ZeroContentLength:

    def response(self, flow):
        if "msdownload" in flow.request.pretty_url and \
                flow.request.method == "HEAD" and\
                "Content-Length" in flow.response.headers:
            ctx.log.info("Msdownload HEAD of len %s seen and set to 0" %
                            flow.response.headers["Content-Length"])
            flow.response.headers["Content-Length"] = '0'

addons = [
    ZeroContentLength()
]

