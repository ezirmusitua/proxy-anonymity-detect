## Proxy Anonymity Detector
[![travis ci](https://travis-ci.org/ezirmusitua/proxy-anonymity-detector.svg?branch=master)](https://travis-ci.org/ezirmusitua/proxy-anonymity-detector)[![Coverage Status](https://coveralls.io/repos/github/ezirmusitua/proxy-anonymity-detector/badge.svg?branch=master)](https://coveralls.io/github/ezirmusitua/proxy-anonymity-detector?branch=master)[![codebeat badge](https://codebeat.co/badges/1bd900a8-4bc3-48b9-bccb-3747061ae910)](https://codebeat.co/projects/github-com-ezirmusitua-proxy-anonymity-detector-master)  
Detect the proxy's anonymity  
  
### Features   
1. Detect the anonymity or proxy  
3. Detect from request object    
    
### Installation  
```bash    
pip install -U proxyAnonymityDetector
```  

### Usage  
```python  
from ProxyAnonymityDetector import Detector as AnonymityDetector, Request as DetectorRequest  

  
# detect anonymity  
## no or elite proxy
detector = AnonymityDetector({'REMOTE_ADDR': '128.101.101.101'})
print(detector.using_proxy)    # probably
print(detector.anonymity)      # ['no', 'elite']  

## no proxy
detector = AnonymityDetector({'REMOTE_ADDR': '128.101.101.101'}, real_ip_address='128.101.101.101')
print(detector.using_proxy)    # no
print(detector.anonymity)      # ['no']  

## elite proxy
detector = AnonymityDetector({'REMOTE_ADDR': '128.101.101.101'}, real_ip_address='128.101.101.100')
print(detector.using_proxy)    # yes
print(detector.anonymity)      # ['elite']

# transparent or anonymous proxy
detector = AnonymityDetector({
    'REMOTE_ADDR': '128.101.101.102',
    'HTTP_VIA': '1.1 128.101.101.102',
    'HTTP_X_FORWARD_FOR': '128.101.101.101'
})
print(detector.anonymity)      # ['anonymous', 'transparent']  

## anonymous proxy
detector = AnonymityDetector({
    'REMOTE_ADDR': '128.101.101.102',
    'HTTP_VIA': '1.1 128.101.101.101, 1.1 128.101.101.102',
    'HTTP_X_FORWARD_FOR': '128.101.101.101, 128.101.101.102'
}, '128.101.101.100)
print(detector.anonymity)      # ['anonymous']  

## transparent proxy
detector = AnonymityDetector({
    'REMOTE_ADDR': '128.101.101.102',
    'HTTP_VIA': '1.1 128.101.101.100, 1.1 128.101.101.102',
    'HTTP_X_FORWARD_FOR': '128.101.101.100, 128.101.101.102'
}, '128.101.101.100')
print(detector.anonymity)      # ['transparent']

# use DetectorRequest to detect framework request
## set field  
request = DetectorRequest()
request.remote_addr = '128.101.101.101'
request.http_via = '128.101.101.101'
request.http_x_forwarded_for = '128.101.101.101'  

## use dict to init
request = DetectorRequest({
    'REMOTE_ADDR': '128.101.101.102',
    'HTTP_VIA': '1.1 128.101.101.102',
    'HTTP_X_FORWARD_FOR': '128.101.102.101, 128.101.201.101'
})  

## from bottle request
request = DetectorRequest.from_bottle(bottle.request)  

## from flask request  
request = DetectorRequest.from_flask(flask.request)  

# detect with DetectorRequest
## create new detector  
request = DetectorRequest.from_bottle(bottle.request)
detector = AnonymityDetector(request)
print(detector.anonymity)  

## use class method
request = DetectorRequest.from_bottle(bottle.request)
print(AnonymityDetector.detect(request, '128.101.101.101'))
```  

### License  
[MIT license](https://opensource.org/licenses/MIT)  

### References  
[HTTP_VIA](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via)  
[X_FORWARDED_FOR](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For)  
