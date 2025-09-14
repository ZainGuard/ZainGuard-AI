"""SIEM connector for ZainGuard AI Platform."""

from typing import Dict, List, Any, Optional
import httpx
import json
from datetime import datetime, timedelta
from loguru import logger

from ..core.config import settings


class SIEMConnector:
    """Connector for Security Information and Event Management systems."""
    
    def __init__(self, base_url: str = None, api_key: str = None, verify_ssl: bool = True):
        self.base_url = base_url or settings.siem_base_url
        self.api_key = api_key or settings.siem_api_key
        self.verify_ssl = verify_ssl and settings.siem_verify_ssl
        self._client = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client with proper configuration."""
        if self._client is None:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=30.0
            )
        return self._client
    
    async def search_logs(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search SIEM logs with a query."""
        try:
            client = await self._get_client()
            
            # Default to last 24 hours if no time range specified
            if not start_time:
                start_time = datetime.utcnow() - timedelta(hours=24)
            if not end_time:
                end_time = datetime.utcnow()
            
            params = {
                "query": query,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "limit": limit
            }
            
            response = await client.get("/api/search", params=params)
            response.raise_for_status()
            
            data = response.json()
            return data.get("results", [])
            
        except Exception as e:
            logger.error(f"Error searching SIEM logs: {e}")
            return []
    
    async def get_alert_details(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific alert."""
        try:
            client = await self._get_client()
            
            response = await client.get(f"/api/alerts/{alert_id}")
            response.raise_for_status()
            
            return response.json()
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"Alert not found: {alert_id}")
                return None
            raise
        except Exception as e:
            logger.error(f"Error getting alert details: {e}")
            return None
    
    async def update_alert_status(
        self,
        alert_id: str,
        status: str,
        priority: int = None,
        analysis: str = None
    ) -> bool:
        """Update alert status and metadata."""
        try:
            client = await self._get_client()
            
            update_data = {"status": status}
            if priority is not None:
                update_data["priority"] = priority
            if analysis:
                update_data["analysis"] = analysis
            
            response = await client.patch(
                f"/api/alerts/{alert_id}",
                json=update_data
            )
            response.raise_for_status()
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
            return False
    
    async def get_alerts_by_status(
        self,
        status: str,
        limit: int = 100,
        start_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get alerts filtered by status."""
        try:
            client = await self._get_client()
            
            params = {
                "status": status,
                "limit": limit
            }
            
            if start_time:
                params["start_time"] = start_time.isoformat()
            
            response = await client.get("/api/alerts", params=params)
            response.raise_for_status()
            
            data = response.json()
            return data.get("alerts", [])
            
        except Exception as e:
            logger.error(f"Error getting alerts by status: {e}")
            return []
    
    async def get_high_priority_alerts(
        self,
        hours: int = 24,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get high priority alerts from the last N hours."""
        try:
            start_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Search for high priority alerts
            query = "priority:>=4 AND status:open"
            alerts = await self.search_logs(
                query=query,
                start_time=start_time,
                limit=limit
            )
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error getting high priority alerts: {e}")
            return []
    
    async def get_security_events(
        self,
        event_types: List[str] = None,
        severity: str = None,
        hours: int = 24,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get security events with optional filters."""
        try:
            start_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Build query
            query_parts = []
            if event_types:
                event_query = " OR ".join([f"event_type:{et}" for et in event_types])
                query_parts.append(f"({event_query})")
            
            if severity:
                query_parts.append(f"severity:{severity}")
            
            query = " AND ".join(query_parts) if query_parts else "*"
            
            events = await self.search_logs(
                query=query,
                start_time=start_time,
                limit=limit
            )
            
            return events
            
        except Exception as e:
            logger.error(f"Error getting security events: {e}")
            return []
    
    async def create_correlation_rule(
        self,
        rule_name: str,
        description: str,
        conditions: List[Dict[str, Any]],
        actions: List[Dict[str, Any]]
    ) -> Optional[str]:
        """Create a new correlation rule in the SIEM."""
        try:
            client = await self._get_client()
            
            rule_data = {
                "name": rule_name,
                "description": description,
                "conditions": conditions,
                "actions": actions,
                "enabled": True
            }
            
            response = await client.post("/api/rules", json=rule_data)
            response.raise_for_status()
            
            data = response.json()
            return data.get("rule_id")
            
        except Exception as e:
            logger.error(f"Error creating correlation rule: {e}")
            return None
    
    async def get_correlation_rules(self) -> List[Dict[str, Any]]:
        """Get all correlation rules."""
        try:
            client = await self._get_client()
            
            response = await client.get("/api/rules")
            response.raise_for_status()
            
            data = response.json()
            return data.get("rules", [])
            
        except Exception as e:
            logger.error(f"Error getting correlation rules: {e}")
            return []
    
    async def test_query(self, query: str) -> Dict[str, Any]:
        """Test a SIEM query and return results summary."""
        try:
            # Test with a short time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=5)
            
            results = await self.search_logs(
                query=query,
                start_time=start_time,
                end_time=end_time,
                limit=10
            )
            
            return {
                "query": query,
                "result_count": len(results),
                "sample_results": results[:3],  # First 3 results as sample
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"Error testing query: {e}")
            return {
                "query": query,
                "result_count": 0,
                "sample_results": [],
                "status": "error",
                "error": str(e)
            }
    
    async def get_siem_health(self) -> Dict[str, Any]:
        """Get SIEM system health status."""
        try:
            client = await self._get_client()
            
            response = await client.get("/api/health")
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logger.error(f"Error getting SIEM health: {e}")
            return {
                "status": "error",
                "message": str(e),
                "connected": False
            }
    
    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None