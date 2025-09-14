"""Threat intelligence API connector for ZainGuard AI Platform."""

from typing import Dict, List, Any, Optional
import httpx
import json
from datetime import datetime
from loguru import logger

from ..core.config import settings


class ThreatIntelAPI:
    """Connector for various threat intelligence APIs."""
    
    def __init__(self):
        self.virustotal_api_key = settings.virustotal_api_key
        self.shodan_api_key = settings.shodan_api_key
        self.abuseipdb_api_key = settings.abuseipdb_api_key
        self._client = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client for API requests."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client
    
    async def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address reputation across multiple sources."""
        result = {
            "ip": ip_address,
            "malicious": False,
            "confidence": 0.0,
            "sources": {},
            "last_updated": datetime.utcnow().isoformat()
        }
        
        # Check VirusTotal
        if self.virustotal_api_key:
            vt_result = await self._check_virustotal_ip(ip_address)
            if vt_result:
                result["sources"]["virustotal"] = vt_result
                if vt_result.get("malicious", False):
                    result["malicious"] = True
                    result["confidence"] = max(result["confidence"], vt_result.get("confidence", 0))
        
        # Check AbuseIPDB
        if self.abuseipdb_api_key:
            abuse_result = await self._check_abuseipdb_ip(ip_address)
            if abuse_result:
                result["sources"]["abuseipdb"] = abuse_result
                if abuse_result.get("malicious", False):
                    result["malicious"] = True
                    result["confidence"] = max(result["confidence"], abuse_result.get("confidence", 0))
        
        # Check Shodan
        if self.shodan_api_key:
            shodan_result = await self._check_shodan_ip(ip_address)
            if shodan_result:
                result["sources"]["shodan"] = shodan_result
        
        return result
    
    async def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation across multiple sources."""
        result = {
            "domain": domain,
            "malicious": False,
            "confidence": 0.0,
            "sources": {},
            "last_updated": datetime.utcnow().isoformat()
        }
        
        # Check VirusTotal
        if self.virustotal_api_key:
            vt_result = await self._check_virustotal_domain(domain)
            if vt_result:
                result["sources"]["virustotal"] = vt_result
                if vt_result.get("malicious", False):
                    result["malicious"] = True
                    result["confidence"] = max(result["confidence"], vt_result.get("confidence", 0))
        
        return result
    
    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash reputation across multiple sources."""
        result = {
            "hash": file_hash,
            "malicious": False,
            "confidence": 0.0,
            "sources": {},
            "last_updated": datetime.utcnow().isoformat()
        }
        
        # Check VirusTotal
        if self.virustotal_api_key:
            vt_result = await self._check_virustotal_hash(file_hash)
            if vt_result:
                result["sources"]["virustotal"] = vt_result
                if vt_result.get("malicious", False):
                    result["malicious"] = True
                    result["confidence"] = max(result["confidence"], vt_result.get("confidence", 0))
        
        return result
    
    async def _check_virustotal_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP address with VirusTotal."""
        try:
            client = await self._get_client()
            
            headers = {"x-apikey": self.virustotal_api_key}
            response = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                # Get detection stats
                stats = attributes.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                total_engines = sum(stats.values())
                
                return {
                    "malicious": malicious_count > 0,
                    "confidence": malicious_count / total_engines if total_engines > 0 else 0,
                    "detection_count": malicious_count,
                    "total_engines": total_engines,
                    "categories": attributes.get("categories", {}),
                    "country": attributes.get("country"),
                    "asn": attributes.get("asn")
                }
            
        except Exception as e:
            logger.warning(f"VirusTotal IP check failed: {e}")
        
        return None
    
    async def _check_virustotal_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain with VirusTotal."""
        try:
            client = await self._get_client()
            
            headers = {"x-apikey": self.virustotal_api_key}
            response = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                # Get detection stats
                stats = attributes.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                total_engines = sum(stats.values())
                
                return {
                    "malicious": malicious_count > 0,
                    "confidence": malicious_count / total_engines if total_engines > 0 else 0,
                    "detection_count": malicious_count,
                    "total_engines": total_engines,
                    "categories": attributes.get("categories", {}),
                    "registrar": attributes.get("registrar"),
                    "creation_date": attributes.get("creation_date")
                }
            
        except Exception as e:
            logger.warning(f"VirusTotal domain check failed: {e}")
        
        return None
    
    async def _check_virustotal_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check file hash with VirusTotal."""
        try:
            client = await self._get_client()
            
            headers = {"x-apikey": self.virustotal_api_key}
            response = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                # Get detection stats
                stats = attributes.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                total_engines = sum(stats.values())
                
                return {
                    "malicious": malicious_count > 0,
                    "confidence": malicious_count / total_engines if total_engines > 0 else 0,
                    "detection_count": malicious_count,
                    "total_engines": total_engines,
                    "file_type": attributes.get("type_description"),
                    "file_size": attributes.get("size"),
                    "first_seen": attributes.get("first_submission_date")
                }
            
        except Exception as e:
            logger.warning(f"VirusTotal hash check failed: {e}")
        
        return None
    
    async def _check_abuseipdb_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP address with AbuseIPDB."""
        try:
            client = await self._get_client()
            
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params=params,
                headers={"Key": self.abuseipdb_api_key}
            )
            
            if response.status_code == 200:
                data = response.json()
                result = data.get("data", {})
                
                abuse_confidence = result.get("abuseConfidencePercentage", 0)
                
                return {
                    "malicious": abuse_confidence > 25,  # Threshold for malicious
                    "confidence": abuse_confidence / 100,
                    "abuse_confidence": abuse_confidence,
                    "country": result.get("countryCode"),
                    "usage_type": result.get("usageType"),
                    "isp": result.get("isp"),
                    "domain": result.get("domain"),
                    "total_reports": result.get("totalReports", 0)
                }
            
        except Exception as e:
            logger.warning(f"AbuseIPDB IP check failed: {e}")
        
        return None
    
    async def _check_shodan_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP address with Shodan."""
        try:
            client = await self._get_client()
            
            response = await client.get(
                f"https://api.shodan.io/shodan/host/{ip_address}",
                params={"key": self.shodan_api_key}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "vulnerabilities": data.get("vulns", []),
                    "services": len(data.get("data", [])),
                    "last_update": data.get("last_update")
                }
            
        except Exception as e:
            logger.warning(f"Shodan IP check failed: {e}")
        
        return None
    
    async def get_threat_feed(self, feed_type: str = "malware") -> List[Dict[str, Any]]:
        """Get threat intelligence feed data."""
        # This is a placeholder for threat feed integration
        # In a real implementation, you would integrate with various threat feeds
        return []
    
    async def search_threat_actors(self, query: str) -> List[Dict[str, Any]]:
        """Search for threat actor information."""
        # This is a placeholder for threat actor database integration
        return []
    
    async def get_malware_families(self, family_name: str = None) -> List[Dict[str, Any]]:
        """Get malware family information."""
        # This is a placeholder for malware family database integration
        return []
    
    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None