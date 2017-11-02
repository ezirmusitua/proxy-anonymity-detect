# -*- coding: utf-8 -*-
import unittest
from ProxyAnonymityDetector import Detector as AnonymityDetector, Request as DetectorRequest


class TestProxyAnonymityDetector(unittest.TestCase):
    def setUp(self):
        pass

    def test_detect_no_or_elite_proxy(self):
        detector = AnonymityDetector({'REMOTE_ADDR': '128.101.101.101'})
        self.assertEqual(detector.using_proxy, 'probably')
        self.assertEqual(detector.anonymity, ['no', 'elite'])

    def test_detect_transparent_proxy(self):
        detector = AnonymityDetector({
            'REMOTE_ADDR': '128.101.101.102',
            'HTTP_VIA': '1.1 128.101.101.101, 1.1 128.101.101.102',
            'HTTP_X_FORWARDED_FOR': '128.101.101.101, 128.101.101.102'
        }, '128.101.101.101')
        self.assertEqual(detector.using_proxy, 'yes')
        self.assertEqual(detector.anonymity, ['transparent'])

    def test_detect_anonymous_proxy(self):
        detector = AnonymityDetector({
            'REMOTE_ADDR': '128.101.101.102',
            'HTTP_VIA': '1.1 128.101.101.103, 1.1 128.101.101.102',
            'HTTP_X_FORWARDED_FOR': '128.101.101.103, 128.101.101.102'
            # pass single proxy, if 2 like '128.101.101.103, 128.101.101.102'
        }, '128.101.101.100')
        self.assertEqual(detector.using_proxy, 'yes')
        self.assertEqual(detector.anonymity, ['anonymous'])

    def test_dict_construct_detector_request(self):
        request_1 = DetectorRequest({
            'REMOTE_ADDR': '128.101.101.102'
        })
        detector = AnonymityDetector(request_1, '128.101.101.102')
        self.assertEqual(detector.run(), ['no'])

    def test_detector_request_from_bottle(self):
        class MockBottleRequest(object):
            def __init__(self):
                self.environ = {'REMOTE_ADDR': '128.101.101.102'}
                self.headers = {}

        request = DetectorRequest.from_bottle(MockBottleRequest())
        detector = AnonymityDetector(request, '128.101.101.102')
        self.assertEqual(detector.run(), ['no'])

    def test_detector_request_from_flask(self):
        class MockFlaskRequest(object):
            def __init__(self):
                self.remote_addr = '128.101.101.102'

                class Headers(object):
                    def __init__(self):
                        self.http_via = ''
                        self.http_x_forwarded_for = ''

                self.headers = Headers()

        request = DetectorRequest.from_flask(MockFlaskRequest())
        detector = AnonymityDetector(request, '128.101.101.102')
        self.assertEqual(detector.run(), ['no'])

    def test_cls_detect(self):
        request_dict = {
            'REMOTE_ADDR': '128.101.101.102'
        }
        anonymity_1 = AnonymityDetector.detect(DetectorRequest.from_dict(request_dict), '128.101.101.102')
        detector = AnonymityDetector(DetectorRequest.from_dict(request_dict), '128.101.101.102')
        self.assertEqual(anonymity_1, ['no'])
        self.assertEqual(anonymity_1, detector.run())

    def tearDown(self):
        pass


if __name__ == '__main__':
    unittest.main()
