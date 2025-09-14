"""Jira integration for ZainGuard AI Platform."""

from typing import Dict, List, Any, Optional
import httpx
import json
from datetime import datetime
from loguru import logger

from ..core.config import settings


class JiraManager:
    """Manager for Jira ticket operations."""
    
    def __init__(self, base_url: str = None, email: str = None, api_token: str = None):
        self.base_url = base_url or settings.jira_base_url
        self.email = email or settings.jira_email
        self.api_token = api_token or settings.jira_api_token
        self._client = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client with Jira authentication."""
        if self._client is None:
            if not all([self.base_url, self.email, self.api_token]):
                raise ValueError("Jira credentials not configured")
            
            auth = (self.email, self.api_token)
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                auth=auth,
                headers=headers,
                timeout=30.0
            )
        return self._client
    
    async def create_ticket(
        self,
        summary: str,
        description: str,
        issue_type: str = "Task",
        priority: str = "Medium",
        assignee: str = None,
        labels: List[str] = None,
        custom_fields: Dict[str, Any] = None
    ) -> Optional[str]:
        """Create a new Jira ticket."""
        try:
            client = await self._get_client()
            
            ticket_data = {
                "fields": {
                    "project": {"key": "SEC"},  # Security project key
                    "summary": summary,
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": description
                                    }
                                ]
                            }
                        ]
                    },
                    "issuetype": {"name": issue_type},
                    "priority": {"name": priority}
                }
            }
            
            if assignee:
                ticket_data["fields"]["assignee"] = {"name": assignee}
            
            if labels:
                ticket_data["fields"]["labels"] = labels
            
            if custom_fields:
                ticket_data["fields"].update(custom_fields)
            
            response = await client.post("/rest/api/3/issue", json=ticket_data)
            response.raise_for_status()
            
            data = response.json()
            ticket_key = data.get("key")
            
            logger.info(f"Created Jira ticket: {ticket_key}")
            return ticket_key
            
        except Exception as e:
            logger.error(f"Error creating Jira ticket: {e}")
            return None
    
    async def get_ticket(self, ticket_key: str) -> Optional[Dict[str, Any]]:
        """Get ticket details by key."""
        try:
            client = await self._get_client()
            
            response = await client.get(f"/rest/api/3/issue/{ticket_key}")
            response.raise_for_status()
            
            data = response.json()
            fields = data.get("fields", {})
            
            return {
                "key": data.get("key"),
                "summary": fields.get("summary"),
                "description": self._extract_description(fields.get("description")),
                "status": fields.get("status", {}).get("name"),
                "priority": fields.get("priority", {}).get("name"),
                "assignee": fields.get("assignee", {}).get("displayName"),
                "reporter": fields.get("reporter", {}).get("displayName"),
                "created": fields.get("created"),
                "updated": fields.get("updated"),
                "labels": fields.get("labels", []),
                "issue_type": fields.get("issuetype", {}).get("name")
            }
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"Ticket not found: {ticket_key}")
                return None
            raise
        except Exception as e:
            logger.error(f"Error getting ticket: {e}")
            return None
    
    async def update_ticket(
        self,
        ticket_key: str,
        updates: Dict[str, Any]
    ) -> bool:
        """Update ticket fields."""
        try:
            client = await self._get_client()
            
            # Convert updates to Jira format
            jira_updates = {"fields": {}}
            
            for field, value in updates.items():
                if field == "summary":
                    jira_updates["fields"]["summary"] = value
                elif field == "description":
                    jira_updates["fields"]["description"] = {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": value
                                    }
                                ]
                            }
                        ]
                    }
                elif field == "priority":
                    jira_updates["fields"]["priority"] = {"name": value}
                elif field == "assignee":
                    jira_updates["fields"]["assignee"] = {"name": value}
                elif field == "labels":
                    jira_updates["fields"]["labels"] = value
                else:
                    # Custom field
                    jira_updates["fields"][field] = value
            
            response = await client.put(f"/rest/api/3/issue/{ticket_key}", json=jira_updates)
            response.raise_for_status()
            
            logger.info(f"Updated Jira ticket: {ticket_key}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating ticket: {e}")
            return False
    
    async def add_comment(self, ticket_key: str, comment: str) -> bool:
        """Add a comment to a ticket."""
        try:
            client = await self._get_client()
            
            comment_data = {
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": comment
                                }
                            ]
                        }
                    ]
                }
            }
            
            response = await client.post(
                f"/rest/api/3/issue/{ticket_key}/comment",
                json=comment_data
            )
            response.raise_for_status()
            
            logger.info(f"Added comment to ticket: {ticket_key}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding comment: {e}")
            return False
    
    async def transition_ticket(self, ticket_key: str, transition_name: str) -> bool:
        """Transition ticket to a new status."""
        try:
            client = await self._get_client()
            
            # Get available transitions
            response = await client.get(f"/rest/api/3/issue/{ticket_key}/transitions")
            response.raise_for_status()
            
            transitions = response.json().get("transitions", [])
            transition_id = None
            
            for transition in transitions:
                if transition["name"].lower() == transition_name.lower():
                    transition_id = transition["id"]
                    break
            
            if not transition_id:
                logger.warning(f"Transition '{transition_name}' not found for ticket {ticket_key}")
                return False
            
            # Perform transition
            transition_data = {"transition": {"id": transition_id}}
            response = await client.post(
                f"/rest/api/3/issue/{ticket_key}/transitions",
                json=transition_data
            )
            response.raise_for_status()
            
            logger.info(f"Transitioned ticket {ticket_key} to {transition_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error transitioning ticket: {e}")
            return False
    
    async def search_tickets(
        self,
        jql: str,
        max_results: int = 50,
        fields: List[str] = None
    ) -> List[Dict[str, Any]]:
        """Search tickets using JQL."""
        try:
            client = await self._get_client()
            
            search_data = {
                "jql": jql,
                "maxResults": max_results,
                "fields": fields or ["key", "summary", "status", "priority", "assignee", "created"]
            }
            
            response = await client.post("/rest/api/3/search", json=search_data)
            response.raise_for_status()
            
            data = response.json()
            tickets = []
            
            for issue in data.get("issues", []):
                fields = issue.get("fields", {})
                tickets.append({
                    "key": issue.get("key"),
                    "summary": fields.get("summary"),
                    "status": fields.get("status", {}).get("name"),
                    "priority": fields.get("priority", {}).get("name"),
                    "assignee": fields.get("assignee", {}).get("displayName"),
                    "created": fields.get("created"),
                    "updated": fields.get("updated")
                })
            
            return tickets
            
        except Exception as e:
            logger.error(f"Error searching tickets: {e}")
            return []
    
    async def get_security_tickets(self, status: str = None) -> List[Dict[str, Any]]:
        """Get security-related tickets."""
        jql = "project = SEC"
        
        if status:
            jql += f" AND status = '{status}'"
        
        return await self.search_tickets(jql)
    
    async def create_incident_ticket(
        self,
        incident_id: str,
        summary: str,
        description: str,
        severity: str = "Medium",
        assignee: str = None
    ) -> Optional[str]:
        """Create a security incident ticket."""
        priority_mapping = {
            "Critical": "Highest",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low"
        }
        
        priority = priority_mapping.get(severity, "Medium")
        
        # Add incident ID to labels
        labels = [f"incident-{incident_id}"]
        
        return await self.create_ticket(
            summary=f"[INCIDENT {incident_id}] {summary}",
            description=description,
            issue_type="Incident",
            priority=priority,
            assignee=assignee,
            labels=labels
        )
    
    async def create_vulnerability_ticket(
        self,
        vuln_id: str,
        summary: str,
        description: str,
        severity: str = "Medium",
        assignee: str = None
    ) -> Optional[str]:
        """Create a vulnerability ticket."""
        priority_mapping = {
            "Critical": "Highest",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low"
        }
        
        priority = priority_mapping.get(severity, "Medium")
        
        # Add vulnerability ID to labels
        labels = [f"vulnerability-{vuln_id}"]
        
        return await self.create_ticket(
            summary=f"[VULN {vuln_id}] {summary}",
            description=description,
            issue_type="Bug",
            priority=priority,
            assignee=assignee,
            labels=labels
        )
    
    def _extract_description(self, description_field: Dict[str, Any]) -> str:
        """Extract text from Jira description field."""
        if not description_field:
            return ""
        
        content = description_field.get("content", [])
        text_parts = []
        
        for item in content:
            if item.get("type") == "paragraph":
                paragraph_content = item.get("content", [])
                for text_item in paragraph_content:
                    if text_item.get("type") == "text":
                        text_parts.append(text_item.get("text", ""))
        
        return "\n".join(text_parts)
    
    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None