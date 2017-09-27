class Detector(object):
    def __init__(self, headers_or_request, real_ip_address=None):
        pass

    def __unicode__(self):
        return 'detector'

    @property
    def anonymity(self):
        pass

    @property
    def using_proxy(self):
        pass

    @classmethod
    def detect(cls, headers_or_request):
        pass
