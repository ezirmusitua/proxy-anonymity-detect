class Request(object):
    def __init__(self, request_dict):
        self.origin = request_dict
        self._remote = request_dict['REMOTE_ADDR']
        self._via = request_dict['HTTP_VIA']
        self._x_forwarded_for = request_dict['HTTP_X_FORWARDED_FOR']

    @property
    def remote_addr(self):
        return self._remote

    @property
    def via(self):
        return self._via

    @property
    def x_forwarded_for(self):
        return self._x_forwarded_for

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
            'HTTP_X_FORWARDED_FOR': flask_request.header.http_x_forwarded_for,
        }
        return cls(request_dict)

    def __unicode__(self):
        return 'Proxy Request Info'
