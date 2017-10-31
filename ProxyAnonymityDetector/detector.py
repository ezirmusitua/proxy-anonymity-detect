class Detector(object):
    def __init__(self, headers_or_request, real_ip_address=None):
        self._remote_addr = headers_or_request.get('REMOTE_ADDR')
        self._http_via = headers_or_request.get('HTTP_VIA')
        self._http_x_forwarded_for = headers_or_request.get('HTTP_X_FORWARDED_FOR')
        self._real_ip_address = real_ip_address
        pass

    def __unicode__(self):
        return 'detector'

    @property
    def remote_addr(self):
        return self._remote_addr

    @remote_addr.setter
    def remote_addr(self, value):
        self._remote_addr = value

    @property
    def http_via(self):
        return self._http_via

    @http_via.setter
    def http_via(self, value):
        self._http_via = value

    @property
    def http_x_forwarded_for(self):
        return self.http_x_forwarded_for

    @http_x_forwarded_for.setter
    def http_x_forwarded_for(self, value):
        # handle str/list
        self.http_x_forwarded_for = value

    @property
    def anonymity(self):
        return ['no']

    @property
    def using_proxy(self):
        return 'no'

    def detect(self):
        return ['no']

    @classmethod
    def detect(cls, headers_or_request):
        pass
