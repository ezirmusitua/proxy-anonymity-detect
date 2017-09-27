class Request(object):
    def __init__(self, request_dict):
        pass

    @classmethod
    def from_dict(cls, request_dict):
        pass

    @classmethod
    def from_bottle(cls, bottle_request):
        pass

    @classmethod
    def from_flask(cls, flask_request):
        pass

    def __unicode__(self):
        return 'request'
