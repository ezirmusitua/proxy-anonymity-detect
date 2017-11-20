class Request(object):
    def __init__(self, request_dict):
        self.origin = request_dict
        self._remote = request_dict.get('REMOTE_ADDR', '')
        self._via = request_dict.get('HTTP_VIA', '')
        self._x_forwarded_for = request_dict.get('HTTP_X_FORWARDED_FOR', '')

    @property
    def remote_addr(self):
        return self._remote

    @property
    def via(self):
        return self._via

    @property
    def x_forwarded_for(self):
        return self._x_forwarded_for

    def get(self, field_name):
        if field_name is 'REMOTE_ADDR':
            return self._remote
        elif field_name is 'VIA' or field_name is 'HTTP_VIA':
            return self._via
        elif field_name is 'X_FORWARDED_FOR' or field_name is 'HTTP_X_FORWARDED_FOR':
            return self._x_forwarded_for
        else:
            raise KeyError('%s is not supported. ' % field_name)

    @classmethod
    def from_dict(cls, dict_request):
        return cls(dict_request)

    @classmethod
    def from_bottle(cls, bottle_request):
        request_dict = {
            'REMOTE_ADDR': bottle_request.environ.get('REMOTE_ADDR'),
            'HTTP_VIA': bottle_request.headers.get('HTTP_VIA'),
            'HTTP_X_FORWARDED_FOR': bottle_request.headers.get('HTTP_X_FORWARDED_FOR'),
        }
        return cls(request_dict)

    @classmethod
    def from_flask(cls, flask_request):
        # Reference 
        # https://stackoverflow.com/questions/12770950/\
        # flask-request-remote-addr-is-wrong-on-webfaction-and-not-showing-real-user-ip
        request_dict = {
            'REMOTE_ADDR': flask_request.remote_addr,
            'HTTP_VIA': flask_request.headers.http_via,
            'HTTP_X_FORWARDED_FOR': flask_request.headers.http_x_forwarded_for,
        }
        return cls(request_dict)

    def __unicode__(self):
        return 'Proxy Request Info'
