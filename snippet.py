import logging
from dataclasses import dataclass
from urllib.parse import urljoin

import requests
from django.conf import settings
from django.core.cache import cache

from .constants import GEO_IP_API_BASE_URL, GEO_IP_CACHE_TIMEOUT

logger = logging.getLogger(__name__)


@dataclass
class GeoIPDetails():
    """DataClass for storing IP Geo Location information"""

    ip: str = None  
    country_code: str = None
    latitude: str = None
    longitude: str = None
    reason: str = None
    success: bool = False


class BaseIpToLocationApi():

    def __init__(self, ip: str, base_url: str, api_key: str) -> None:
        self.ip = ip
        self.base_url = base_url
        self.api_key = api_key

    def call_api(self):
        raise NotImplementedError()

    def get_details(self):
        raise NotImplementedError()


class GeoIpApiCo(BaseIpToLocationApi):
    """https://ipapi.co/api/"""

    def __init__(self, ip: str, base_url: str, api_key: str = '') -> None:
        super().__init__(ip, base_url, api_key)

    def call_api(self):
        url = urljoin(self.base_url, f'{self.ip}/json')
        params = {'key': self.api_key}
        try:
            response = requests.request(
                'GET',
                url,
                params=params,
                timeout=settings.REQUESTS_TIMEOUT,
            )
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': True, 'reason': str(e)}

    def get_details(self):
        if not settings.IP_API_ENABLED:
            return GeoIPDetails(**{
                'success': False,
                'reason': f'IP API is disabled for {settings.LEVEL} environment.'
            })

        response = self.call_api()
        error = response.get('error')
        if error:
            logger.error(
                'There was an error at https://ipapi.co API %s %s',
                response.get('reason'),
                response.get('message')
            )
            return GeoIPDetails(**{
                'success': False,
                'reason': 'Error processing location request'
            })

        json_response = {
            'success': True,
            'ip': self.ip,
            'country_code': response.get('country_code'),
            'latitude': response.get('latitude'),
            'longitude': response.get('longitude')
        }
        return GeoIPDetails(**json_response)


def get_geo_ip_details(request):
    headers = request.META
    forwarded_for_header = headers.get('HTTP_X_FORWARDED_FOR')
    if forwarded_for_header:
        ip_addr = forwarded_for_header.split(',')[-1].strip()
    else:
        ip_addr = headers.get('REMOTE_ADDR')

    cache_key = f'geo-ip-{ip_addr}-response'
    cache_value = cache.get(cache_key)
    if cache_value:
        return cache_value

    geo_ip = GeoIpApiCo(ip_addr, GEO_IP_API_BASE_URL, settings.IP_API_API_KEY)

    geo_ip_details = geo_ip.get_details()
    cache.set(cache_key, geo_ip_details, timeout=GEO_IP_CACHE_TIMEOUT)

    return geo_ip_details
