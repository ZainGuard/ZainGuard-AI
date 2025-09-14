"""Database connector for ZainGuard AI Platform."""

from typing import Dict, List, Any, Optional, Union
from abc import ABC, abstractmethod
import json
import sqlite3
from datetime import datetime
from pathlib import Path
import asyncio
from loguru import logger

from .config import settings


class VectorStore(ABC):
    """Abstract base class for vector stores."""
    
    @abstractmethod
    async def add_documents(self, documents: List[Dict[str, Any]]) -> List[str]:
        """Add documents to the vector store."""
        pass
    
    @abstractmethod
    async def search(self, query: str, k: int = 5) -> List[Dict[str, Any]]:
        """Search for similar documents."""
        pass
    
    @abstractmethod
    async def delete_documents(self, document_ids: List[str]) -> bool:
        """Delete documents by IDs."""
        pass


class ChromaVectorStore(VectorStore):
    """ChromaDB vector store implementation."""
    
    def __init__(self, collection_name: str = "zain_guard_kb", persist_directory: str = None):
        self.collection_name = collection_name
        self.persist_directory = persist_directory or settings.vector_db_path
        self._client = None
        self._collection = None
    
    async def _get_client(self):
        """Get ChromaDB client, creating if necessary."""
        if self._client is None:
            try:
                import chromadb
                from chromadb.config import Settings
                
                # Ensure persist directory exists
                Path(self.persist_directory).mkdir(parents=True, exist_ok=True)
                
                self._client = chromadb.PersistentClient(
                    path=self.persist_directory,
                    settings=Settings(anonymized_telemetry=False)
                )
                
                # Get or create collection
                self._collection = self._client.get_or_create_collection(
                    name=self.collection_name
                )
                
            except ImportError:
                raise ImportError("ChromaDB package not installed. Run: pip install chromadb")
        return self._client, self._collection
    
    async def add_documents(self, documents: List[Dict[str, Any]]) -> List[str]:
        """Add documents to the vector store."""
        try:
            client, collection = await self._get_client()
            
            # Prepare documents for ChromaDB
            texts = [doc.get("content", "") for doc in documents]
            metadatas = [doc.get("metadata", {}) for doc in documents]
            ids = [doc.get("id", f"doc_{i}") for i, doc in enumerate(documents)]
            
            # Add to collection
            collection.add(
                documents=texts,
                metadatas=metadatas,
                ids=ids
            )
            
            logger.info(f"Added {len(documents)} documents to vector store")
            return ids
            
        except Exception as e:
            logger.error(f"Error adding documents to vector store: {e}")
            raise
    
    async def search(self, query: str, k: int = 5) -> List[Dict[str, Any]]:
        """Search for similar documents."""
        try:
            client, collection = await self._get_client()
            
            results = collection.query(
                query_texts=[query],
                n_results=k
            )
            
            # Format results
            documents = []
            if results["documents"] and results["documents"][0]:
                for i, doc in enumerate(results["documents"][0]):
                    documents.append({
                        "id": results["ids"][0][i] if results["ids"] and results["ids"][0] else None,
                        "content": doc,
                        "metadata": results["metadatas"][0][i] if results["metadatas"] and results["metadatas"][0] else {},
                        "distance": results["distances"][0][i] if results["distances"] and results["distances"][0] else None
                    })
            
            return documents
            
        except Exception as e:
            logger.error(f"Error searching vector store: {e}")
            raise
    
    async def delete_documents(self, document_ids: List[str]) -> bool:
        """Delete documents by IDs."""
        try:
            client, collection = await self._get_client()
            collection.delete(ids=document_ids)
            logger.info(f"Deleted {len(document_ids)} documents from vector store")
            return True
        except Exception as e:
            logger.error(f"Error deleting documents from vector store: {e}")
            return False


class DatabaseConnector:
    """Main database connector for the platform."""
    
    def __init__(self, database_url: str = None):
        self.database_url = database_url or settings.database_url
        self.vector_store = ChromaVectorStore()
        self._connection = None
    
    async def _get_connection(self):
        """Get database connection, creating if necessary."""
        if self._connection is None:
            if self.database_url.startswith("sqlite"):
                # SQLite connection
                db_path = self.database_url.replace("sqlite:///", "")
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)
                self._connection = sqlite3.connect(db_path, check_same_thread=False)
                self._connection.row_factory = sqlite3.Row
                await self._create_tables()
            else:
                # For other databases, you would implement connection logic here
                raise NotImplementedError(f"Database type not supported: {self.database_url}")
        
        return self._connection
    
    async def _create_tables(self):
        """Create necessary database tables."""
        connection = await self._get_connection()
        cursor = connection.cursor()
        
        # Agents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                agent_type TEXT NOT NULL,
                config TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Tasks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                task_type TEXT NOT NULL,
                input_data TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                result TEXT,
                error TEXT,
                priority INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (agent_id) REFERENCES agents (id)
            )
        """)
        
        # Knowledge base table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_base (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                category TEXT,
                tags TEXT,
                source TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Security events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                raw_data TEXT NOT NULL,
                processed_data TEXT,
                status TEXT DEFAULT 'new',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP
            )
        """)
        
        connection.commit()
        logger.info("Database tables created successfully")
    
    async def save_agent(self, agent_data: Dict[str, Any]) -> str:
        """Save agent data to database."""
        try:
            connection = await self._get_connection()
            cursor = connection.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO agents 
                (id, name, description, agent_type, config, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                agent_data["id"],
                agent_data["name"],
                agent_data["description"],
                agent_data["agent_type"],
                json.dumps(agent_data.get("config", {}))
            ))
            
            connection.commit()
            logger.info(f"Saved agent: {agent_data['name']}")
            return agent_data["id"]
            
        except Exception as e:
            logger.error(f"Error saving agent: {e}")
            raise
    
    async def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get agent data from database."""
        try:
            connection = await self._get_connection()
            cursor = connection.cursor()
            
            cursor.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    "id": row["id"],
                    "name": row["name"],
                    "description": row["description"],
                    "agent_type": row["agent_type"],
                    "config": json.loads(row["config"]) if row["config"] else {},
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
            return None
            
        except Exception as e:
            logger.error(f"Error getting agent: {e}")
            return None
    
    async def save_task(self, task_data: Dict[str, Any]) -> str:
        """Save task data to database."""
        try:
            connection = await self._get_connection()
            cursor = connection.cursor()
            
            cursor.execute("""
                INSERT INTO tasks 
                (id, agent_id, task_type, input_data, status, result, error, priority, created_at, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task_data["id"],
                task_data["agent_id"],
                task_data["task_type"],
                json.dumps(task_data["input_data"]),
                task_data.get("status", "pending"),
                json.dumps(task_data.get("result")) if task_data.get("result") else None,
                task_data.get("error"),
                task_data.get("priority", 1),
                task_data.get("created_at", datetime.utcnow().isoformat()),
                task_data.get("started_at"),
                task_data.get("completed_at")
            ))
            
            connection.commit()
            return task_data["id"]
            
        except Exception as e:
            logger.error(f"Error saving task: {e}")
            raise
    
    async def update_task(self, task_id: str, updates: Dict[str, Any]) -> bool:
        """Update task data in database."""
        try:
            connection = await self._get_connection()
            cursor = connection.cursor()
            
            set_clauses = []
            values = []
            
            for key, value in updates.items():
                if key in ["result", "input_data"]:
                    set_clauses.append(f"{key} = ?")
                    values.append(json.dumps(value))
                else:
                    set_clauses.append(f"{key} = ?")
                    values.append(value)
            
            values.append(task_id)
            
            query = f"UPDATE tasks SET {', '.join(set_clauses)} WHERE id = ?"
            cursor.execute(query, values)
            
            connection.commit()
            return cursor.rowcount > 0
            
        except Exception as e:
            logger.error(f"Error updating task: {e}")
            return False
    
    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task data from database."""
        try:
            connection = await self._get_connection()
            cursor = connection.cursor()
            
            cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    "id": row["id"],
                    "agent_id": row["agent_id"],
                    "task_type": row["task_type"],
                    "input_data": json.loads(row["input_data"]) if row["input_data"] else {},
                    "status": row["status"],
                    "result": json.loads(row["result"]) if row["result"] else None,
                    "error": row["error"],
                    "priority": row["priority"],
                    "created_at": row["created_at"],
                    "started_at": row["started_at"],
                    "completed_at": row["completed_at"]
                }
            return None
            
        except Exception as e:
            logger.error(f"Error getting task: {e}")
            return None
    
    async def save_knowledge_document(self, document_data: Dict[str, Any]) -> str:
        """Save knowledge document to database and vector store."""
        try:
            # Save to SQLite
            connection = await self._get_connection()
            cursor = connection.cursor()
            
            doc_id = document_data.get("id", f"doc_{datetime.utcnow().timestamp()}")
            
            cursor.execute("""
                INSERT OR REPLACE INTO knowledge_base 
                (id, title, content, category, tags, source, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                doc_id,
                document_data["title"],
                document_data["content"],
                document_data.get("category"),
                json.dumps(document_data.get("tags", [])),
                document_data.get("source")
            ))
            
            connection.commit()
            
            # Also add to vector store for semantic search
            await self.vector_store.add_documents([{
                "id": doc_id,
                "content": document_data["content"],
                "metadata": {
                    "title": document_data["title"],
                    "category": document_data.get("category"),
                    "tags": document_data.get("tags", []),
                    "source": document_data.get("source")
                }
            }])
            
            logger.info(f"Saved knowledge document: {document_data['title']}")
            return doc_id
            
        except Exception as e:
            logger.error(f"Error saving knowledge document: {e}")
            raise
    
    async def search_knowledge(self, query: str, k: int = 5) -> List[Dict[str, Any]]:
        """Search knowledge base using vector similarity."""
        try:
            return await self.vector_store.search(query, k)
        except Exception as e:
            logger.error(f"Error searching knowledge base: {e}")
            return []
    
    async def save_security_event(self, event_data: Dict[str, Any]) -> str:
        """Save security event to database."""
        try:
            connection = await self._get_connection()
            cursor = connection.cursor()
            
            event_id = event_data.get("id", f"event_{datetime.utcnow().timestamp()}")
            
            cursor.execute("""
                INSERT INTO security_events 
                (id, event_type, severity, source, raw_data, processed_data, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                event_id,
                event_data["event_type"],
                event_data["severity"],
                event_data["source"],
                json.dumps(event_data["raw_data"]),
                json.dumps(event_data.get("processed_data", {})),
                event_data.get("status", "new")
            ))
            
            connection.commit()
            logger.info(f"Saved security event: {event_id}")
            return event_id
            
        except Exception as e:
            logger.error(f"Error saving security event: {e}")
            raise
    
    async def get_security_events(
        self, 
        event_type: str = None, 
        severity: str = None, 
        status: str = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get security events with optional filters."""
        try:
            connection = await self._get_connection()
            cursor = connection.cursor()
            
            query = "SELECT * FROM security_events WHERE 1=1"
            params = []
            
            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            if status:
                query += " AND status = ?"
                params.append(status)
            
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            events = []
            for row in rows:
                events.append({
                    "id": row["id"],
                    "event_type": row["event_type"],
                    "severity": row["severity"],
                    "source": row["source"],
                    "raw_data": json.loads(row["raw_data"]) if row["raw_data"] else {},
                    "processed_data": json.loads(row["processed_data"]) if row["processed_data"] else {},
                    "status": row["status"],
                    "created_at": row["created_at"],
                    "processed_at": row["processed_at"]
                })
            
            return events
            
        except Exception as e:
            logger.error(f"Error getting security events: {e}")
            return []
    
    async def close(self):
        """Close database connections."""
        if self._connection:
            self._connection.close()
            self._connection = None


# Global database connector instance
db_connector = DatabaseConnector()