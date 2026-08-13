"""
chroma_client.py

ChromaDB Vector Store Client for Security Remediation Knowledge Base.
Provides vector storage, embedding generation, and similarity search.
Includes built-in fallback engine for offline or lightweight environments.
"""

from __future__ import annotations

import os
import json
import math
import logging
root_env = Path(__file__).parent.parent.parent / ".env"
ai_env = Path(__file__).parent.parent / ".env"
if root_env.exists():
    load_dotenv(root_env)
if ai_env.exists():
    load_dotenv(ai_env, override=True)

logger = logging.getLogger("DevSecOps-AI-Chroma")



class FallbackVectorStore:
    """
    In-memory TF-IDF cosine similarity fallback vector engine when ChromaDB is absent.
    """

    def __init__(self, persist_path: Optional[Path] = None):
        self.persist_path = persist_path
        self.documents: List[str] = []
        self.metadatas: List[Dict[str, Any]] = []
        self.ids: List[str] = []
        self._load()

    def _load(self):
        if self.persist_path and self.persist_path.exists():
            try:
                with open(self.persist_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.documents = data.get("documents", [])
                    self.metadatas = data.get("metadatas", [])
                    self.ids = data.get("ids", [])
            except Exception as e:
                logger.warning(f"Could not load fallback vector store: {e}")

    def _save(self):
        if self.persist_path:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persist_path, "w", encoding="utf-8") as f:
                json.dump({
                    "documents": self.documents,
                    "metadatas": self.metadatas,
                    "ids": self.ids
                }, f, indent=2)

    def _tokenize(self, text: str) -> List[str]:
        return [w.lower() for w in text.replace("-", " ").replace("_", " ").split() if len(w) > 1]

    def add(self, ids: List[str], documents: List[str], metadatas: List[Dict[str, Any]]):
        for id_, doc, meta in zip(ids, documents, metadatas):
            if id_ in self.ids:
                idx = self.ids.index(id_)
                self.documents[idx] = doc
                self.metadatas[idx] = meta
            else:
                self.ids.append(id_)
                self.documents.append(doc)
                self.metadatas.append(meta)
        self._save()

    def query(self, query_text: str, n_results: int = 3) -> Dict[str, Any]:
        query_tokens = set(self._tokenize(query_text))
        scores = []
        for idx, doc in enumerate(self.documents):
            doc_tokens = self._tokenize(doc)
            meta_tokens = self._tokenize(json.dumps(self.metadatas[idx]))
            all_tokens = doc_tokens + meta_tokens
            if not all_tokens:
                score = 0.0
            else:
                matches = sum(1 for t in query_tokens if t in all_tokens)
                score = matches / (math.sqrt(len(query_tokens)) * math.sqrt(len(all_tokens)) + 1e-5)
            scores.append((score, idx))

        scores.sort(key=lambda x: x[0], reverse=True)
        top_indices = [idx for _, idx in scores[:n_results]]

        return {
            "ids": [[self.ids[i] for i in top_indices]],
            "documents": [[self.documents[i] for i in top_indices]],
            "metadatas": [[self.metadatas[i] for i in top_indices]],
            "distances": [[1.0 - scores[i][0] for i in range(min(n_results, len(scores)))]]
        }

    def count(self) -> int:
        return len(self.ids)

    def reset(self):
        self.documents = []
        self.metadatas = []
        self.ids = []
        self._save()


class ChromaClient:
    """
    Wrapper for ChromaDB Vector Client with automatic persistence and fallback handling.
    """

    def __init__(self, persist_dir: Optional[str] = None, collection_name: Optional[str] = None):
        self.persist_dir = Path(persist_dir or os.getenv("CHROMA_PERSIST_DIR", "ai/chroma_db"))
        self.collection_name = collection_name or os.getenv("CHROMA_COLLECTION_NAME", "security_remediations")
        self.client = None
        self.collection = None
        self.fallback_store = None
        self._init_chroma()

    def _init_chroma(self):
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        try:
            import chromadb
            from chromadb.config import Settings

            self.client = chromadb.PersistentClient(
                path=str(self.persist_dir),
                settings=Settings(anonymized_telemetry=False, allow_reset=True)
            )
            self.collection = self.client.get_or_create_collection(name=self.collection_name)
            logger.info(f"Initialized ChromaDB PersistentClient at '{self.persist_dir}', collection: '{self.collection_name}'")
        except Exception as err:
            logger.warning(f"ChromaDB initialization failed ({err}). Using fallback vector store.")
            fallback_file = self.persist_dir / "fallback_store.json"
            self.fallback_store = FallbackVectorStore(persist_path=fallback_file)

    def add_documents(self, ids: List[str], documents: List[str], metadatas: List[Dict[str, Any]]) -> bool:
        """Add documents and metadatas into the vector store."""
        if not ids or not documents:
            return False

        try:
            if self.collection is not None:
                self.collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
                logger.info(f"Successfully upserted {len(ids)} documents into ChromaDB collection '{self.collection_name}'.")
                return True
            elif self.fallback_store is not None:
                self.fallback_store.add(ids=ids, documents=documents, metadatas=metadatas)
                logger.info(f"Successfully added {len(ids)} documents to fallback vector store.")
                return True
        except Exception as err:
            logger.error(f"Error adding documents: {err}")
            return False
        return False

    def query(self, query_text: str, n_results: int = 3, where: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Query vector database for similar security remediation records."""
        try:
            if self.collection is not None:
                kwargs = {"query_texts": [query_text], "n_results": n_results}
                if where:
                    kwargs["where"] = where
                return self.collection.query(**kwargs)
            elif self.fallback_store is not None:
                return self.fallback_store.query(query_text=query_text, n_results=n_results)
        except Exception as err:
            logger.error(f"Error querying vector database: {err}")

        return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

    def count(self) -> int:
        """Return total document count in collection."""
        if self.collection is not None:
            return self.collection.count()
        elif self.fallback_store is not None:
            return self.fallback_store.count()
        return 0

    def reset(self):
        """Reset and purge collection."""
        if self.collection is not None:
            try:
                self.client.delete_collection(self.collection_name)
                self.collection = self.client.get_or_create_collection(name=self.collection_name)
            except Exception as err:
                logger.error(f"Error deleting Chroma collection: {err}")
        elif self.fallback_store is not None:
            self.fallback_store.reset()
