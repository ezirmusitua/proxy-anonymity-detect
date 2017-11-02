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
        # empty anonymity list
        if not self._anonymity:
            return 'unknown'
        if len(self._anonymity) is 1 and self._anonymity[0] == 'no':
            return 'no'
        if len(self._anonymity) is 1 and (self._anonymity[0] == 'transparent' or self._anonymity[0] == 'anonymous'):
            return 'yes'
        return 'probably'

    def run(self):
        return Detector.detect(self.request)

    @classmethod
    def detect(cls, headers_or_request, real_ip_addr=None):
        res = list()
        remote_addr = headers_or_request.get('REMOTE_ADDR')
        via_addrs = split_via(headers_or_request.get('HTTP_VIA'))
        x_forwarded_for_addrs = split_x_forwarded_for(headers_or_request.get('HTTP_X_FORWARDED_FOR'))
        rm_is_ls_p = remote_addr == via_addrs[-1] or remote_addr == x_forwarded_for_addrs[-1]
        if not x_forwarded_for_addrs[0] and not via_addrs[0] and remote_addr == real_ip_addr:
            res.append('no')
        is_lc = via_addrs[0] == x_forwarded_for_addrs[0] == real_ip_addr
        if is_lc and rm_is_ls_p:
            res.append('transparent')
        no_lc_ip = via_addrs[0] == x_forwarded_for_addrs[0] != real_ip_addr
        if rm_is_ls_p and no_lc_ip:
            res.append('anonymous')
        return res


def split_via(via_str):
    addr_with_version_list = via_str.split(', ')
    return [av.split(' ')[1] for av in addr_with_version_list]


def split_x_forwarded_for(x_forwarded_for_str):
    return x_forwarded_for_str.split(', ')
