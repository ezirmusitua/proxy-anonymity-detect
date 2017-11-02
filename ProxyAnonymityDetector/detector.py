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
            self._anonymity = Detector.detect(self.request, self._real_ip_address)
            self._anonymity.sort()
        return self._anonymity

    @property
    def using_proxy(self):
        # empty anonymity list
        if not self.anonymity:
            return 'unknown'
        if len(self.anonymity) > 1:
            if self.anonymity == ['anonymous', 'transparent']:
                return 'yes'
            return 'probably'
        elif len(self.anonymity) and self.anonymity[0] != 'no':
            return 'yes'
        else:
            return 'no'

    def run(self):
        return Detector.detect(self.request, self._real_ip_address)

    @classmethod
    def detect(cls, headers_or_request, real_ip_addr=None):
        rm_addr = headers_or_request.get('REMOTE_ADDR')
        via_addrs = split_via(headers_or_request.get('HTTP_VIA'))
        x_forwarded_for_addrs = split_x_forwarded_for(headers_or_request.get('HTTP_X_FORWARDED_FOR'))
        no_real_ip = not real_ip_addr
        rm_is_real = not no_real_ip and real_ip_addr == rm_addr
        no_via_and_x_forwarded_for = not via_addrs and not x_forwarded_for_addrs
        if no_real_ip and no_via_and_x_forwarded_for:
            return ['no', 'elite']
        if rm_is_real and no_via_and_x_forwarded_for:
            return ['no']
        if not rm_is_real and no_via_and_x_forwarded_for:
            return ['elite']
        rm_is_last_proxy = rm_addr == via_addrs[-1] == x_forwarded_for_addrs[-1]
        if no_real_ip and rm_is_last_proxy:
            return ['transparent', 'anonymous']
        real_is_first = real_ip_addr == via_addrs[0] == x_forwarded_for_addrs[0]
        if not no_real_ip and rm_is_last_proxy and real_is_first:
            return ['transparent']
        if not no_real_ip and rm_is_last_proxy and not real_is_first:
            return ['anonymous']
        return []


def split_via(via_str):
    if not via_str:
        return None
    addr_with_version_list = via_str.split(', ')
    return [av.split(' ')[1] for av in addr_with_version_list]


def split_x_forwarded_for(x_forwarded_for_str):
    if not x_forwarded_for_str:
        return None
    return x_forwarded_for_str.split(', ')
