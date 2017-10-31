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

    def test_detect_with_real_ip(self):
        detector = AnonymityDetector({'REMOTE_ADDR': '128.101.101.101'}, real_ip_address='128.101.101.101')
        self.assertEqual(detector.using_proxy, 'yes')
        self.assertEqual(detector.anonymity, ['no'])

    def test_detect_transparent_proxy(self):
        detector = AnonymityDetector({
            'REMOTE_ADDR': '128.101.101.102',
            'HTTP_VIA': '1.1 128.101.101.102',
            'HTTP_X_FORWARDED_FOR': '128.101.101.101'
        })
        self.assertEqual(detector.using_proxy, 'yes')
        self.assertEqual(detector.anonymity, ['transparent'])

    def test_detect_anonymous_proxy(self):
        detector = AnonymityDetector({
            'REMOTE_ADDR': '128.101.101.102',
            'HTTP_VIA': '1.1 128.101.101.102',
            'HTTP_X_FORWARDED_FOR': '128.101.101.102'  # pass single proxy, if 2 like '128.101.101.103, 128.101.101.102'
        })
        self.assertEqual(detector.using_proxy, 'yes')
        self.assertEqual(detector.anonymity, ['anonymous'])

    def test_detect_distorting_proxy(self):
        detector = AnonymityDetector({
            'REMOTE_ADDR': '128.101.101.102',
            'HTTP_VIA': '1.1 128.101.101.102',
            'HTTP_X_FORWARDED_FOR': '128.101.102.101, 128.101.201.101'
        })
        self.assertEqual(detector.using_proxy, 'yes')
        self.assertEqual(detector.anonymity, ['distorting'])

    def test_dict_construct_detector_request(self):
        request_1 = DetectorRequest({
            'REMOTE_ADDR': '128.101.101.102',
            'HTTP_VIA': '1.1 128.101.101.102',
            'HTTP_X_FORWARDED_FOR': '128.101.102.101, 128.101.201.101'
        })
        anonymity_1 = AnonymityDetector(request_1)
        self.assertEqual(anonymity_1, ['distorting'])

    def test_detector_request_from_bottle(self):
        mock_bottle_request = {
            'REMOTE_ADDR': '128.101.101.102',
            'HTTP_VIA': '1.1 128.101.101.102',
            'HTTP_X_FORWARDED_FOR': '128.101.102.101, 128.101.201.101'
        }
        request = DetectorRequest.from_bottle(mock_bottle_request)
        anonymity_1 = AnonymityDetector(request)
        self.assertEqual(anonymity_1, ['distorting'])

    def test_detector_request_from_flask(self):
        mock_flask_request = {
            'REMOTE_ADDR': '128.101.101.102',
            'HTTP_VIA': '1.1 128.101.101.102',
            'HTTP_X_FORWARDED_FOR': '128.101.102.101, 128.101.201.101'
        }
        request = DetectorRequest.from_flask(mock_flask_request)
        anonymity_1 = AnonymityDetector(request)
        self.assertEqual(anonymity_1, ['distorting'])

    def test_cls_detect(self):
        request_dict = {
            'REMOTE_ADDR': '128.101.101.102',
            'HTTP_VIA': '1.1 128.101.101.102',
            'HTTP_X_FORWARDED_FOR': '128.101.102.101, 128.101.201.101'
        }
        anonymity_1 = AnonymityDetector.detect(DetectorRequest.from_dict(request_dict))
        anonymity_2 = AnonymityDetector(DetectorRequest.from_dict(request_dict))
        self.assertEqual(anonymity_1, ['distorting'])
        self.assertEqual(anonymity_1, anonymity_2)

    def tearDown(self):
        pass


if __name__ == '__main__':
    unittest.main()
