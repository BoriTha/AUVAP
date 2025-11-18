from sentence_transformers import SentenceTransformer
import pickle
import numpy as np
from pathlib import Path
from typing import List, Dict

class RAGManager:
    """
    Lightweight RAG system for exploit knowledge retrieval.
    Uses sentence-transformers for embedding and numpy for similarity search.
    """
    
    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        db_path: str = "data/agent_results/rag_exploits.pkl",
        top_k: int = 3
    ):
        self.model = SentenceTransformer(model_name)
        self.db_path = Path(db_path)
        self.top_k = top_k
        
        # Load or initialize database
        self.exploits = []  # List of exploit records
        self.embeddings = None  # Numpy array of embeddings
        self._load_db()
    
    def _load_db(self):
        """Load existing database"""
        if self.db_path.exists():
            with open(self.db_path, 'rb') as f:
                data = pickle.load(f)
                self.exploits = data.get('exploits', [])
                self.embeddings = data.get('embeddings')
    
    def save_db(self):
        """Save database to disk"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, 'wb') as f:
            pickle.dump({
                'exploits': self.exploits,
                'embeddings': self.embeddings
            }, f)
    
    def add_exploit(
        self,
        service: str,
        port: int,
        code: str,
        success: bool,
        cve: str = None,
        os_type: str = None
    ):
        """Add a new exploit to the database"""
        exploit = {
            'service': service,
            'port': port,
            'code': code,
            'success': success,
            'cve': cve,
            'os_type': os_type,
            'text': f"{service} port {port} {cve or ''} {os_type or ''}"
        }
        
        self.exploits.append(exploit)
        
        # Recompute embeddings
        texts = [e['text'] for e in self.exploits]
        self.embeddings = self.model.encode(texts, convert_to_numpy=True)
        
        self.save_db()
    
    def retrieve_similar(self, query: str, only_successful: bool = True) -> List[Dict]:
        """
        Retrieve most similar exploits from database.
        
        Args:
            query: Search query (e.g., "vsftpd 2.3.4 port 21")
            only_successful: Only return successful exploits
        
        Returns:
            List of top-k similar exploits
        """
        if len(self.exploits) == 0:
            return []
        
        # Encode query
        query_embedding = self.model.encode([query], convert_to_numpy=True)
        
        # Compute cosine similarity
        similarities = np.dot(self.embeddings, query_embedding.T).flatten()
        
        # Get top-k indices
        top_indices = np.argsort(similarities)[::-1][:self.top_k * 2]  # Get extra in case filtering
        
        # Filter and return
        results = []
        for idx in top_indices:
            exploit = self.exploits[idx]
            if only_successful and not exploit['success']:
                continue
            
            results.append({
                **exploit,
                'similarity': float(similarities[idx])
            })
            
            if len(results) >= self.top_k:
                break
        
        return results
