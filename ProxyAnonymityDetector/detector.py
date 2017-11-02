from .request import Request


class Detector(object):
    def __init__(self, headers_or_request, real_ip_address=None):
        if not isinstance(headers_or_request, dict) and not isinstance(headers_or_request, Request):
            raise TypeError('Invalid request type')
        self.request = Request(headers_or_request) if isinstance(headers_or_request, dict) else headers_or_request
        self._real_ip_address = real_ip_address
        self._anonymity = []

    def __unicode__(self):
        return 'detector'

    @property
    def remote_addr(self):
        return self.request.remote_addr

    @property
    def http_via(self):
        return self.request.via

    @property
    def http_x_forwarded_for(self):
        return self.request.x_forwarded_for

    @property
    def anonymity(self):
        if not self._anonymity:
            self._anonymity = Detector.detect(self.request)
        return self._anonymity

    @property
    def using_proxy(self):
        return 'no'

    def run(self):
        return Detector.detect(self.request)

    @classmethod
    def detect(cls, headers_or_request):
        return ['no']
