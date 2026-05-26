import os
import requests
import numpy as np
from bs4 import BeautifulSoup
from fastmcp import FastMCP
from langchain_text_splitters import RecursiveCharacterTextSplitter
from sentence_transformers import SentenceTransformer
import faiss

#========================================
# 1.INITIALIZATION & CORE CONFIGURATION
#========================================

#Intialize the FastMCP Server
mcp = FastMCP("Cyber-Security-Scanner")

# Using a lightweight, fast local embedding model (384 dimensions)
print("Loading Embedding Mmodel (all-MiniLM-L6-v2)....")
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
text_splitter = RecursiveCharacterTextSplitter(chunk_size=600, chunk_overlap=60)

# Local RAG Knowledge Layer (In-Memory FAISS Database)
vector_dimensions = 384
index = faiss.IndexFlatL2(vector_dimensions)
chunks_database = [] #Maps FAISS index tracking IDs back to raw text strings

#Target signals to watch out for during crawl (Mimics Feature/Signal Extraction Layer)
SECURITY_SIGNALS = [
    "cve", "vulnerability", "exploit", "patch","deprecated",
    "nginx", "apache", "wordpress", "sql", "cross-site", "auth"
]

#========================================
#2. TOOL LAYER 1: SMART CRAWLER & RAG
#========================================

@mcp.tool()
def crawl_and_extract_signals(url : str) -> str:
    """
    Crawls a target website, extracts relevant text, extracts cybersecurity signals,
    and saves the vectorized data into the RAG Knowledge Layer.
    """
    global index, chunks_database

    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)CyberScanner/1.0"}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        #Parse HTML & clean up scripts/styles
        soup = BeautifulSoup(response.text, "html.parser")
        for script in soup(["script", "style"]):
          script.extract()

        raw_text = soup.get_text(separator=" ")
        clean_text = " ".join(raw_text.split())

        #Smart Feature/Signal Extraction
        detected_signals = [word for word in SECURITY_SIGNALS if word in clean_text.lower()]

        #Document Chunking
        chunks = text_splitter.split_text(clean_text)
        if not chunks:
            return f"Crawl complete for {url}, but no readable text context was found."


        #Generate Embeddings and Push to FAISS Index
        embeddings = embedding_model.encode(chunks)
        embeddings_np = np.array(embeddings).astype("float32")

        index.add(embeddings_np)
        chunks_database.extend(chunks)

        summary = (
            f"===CRAWL SUCCESSFUL ===\n"
            f"Target: {url}\n"
            f"Processed Chunks Added to RAG: {len(chunks)}\n"
            f"Security Signals Flagged: {', '.join(detected_signals) if detected_signals else 'None'}\n"
        )
        return summary

    except Exception as e:
        return f"Error during crawl execution on {url}: {str(e)}"

@mcp.tool()
def query_knowledge_layer(query: str, top_k: int = 3) -> str:
    """
    Queries the local RAG knowledge base to retrieve crawled security context matching your query string.
    """
    global index, chunks_database

    if index.ntotal == 0:
        return "The RAG Knowledge Layer is currently empty. Execute 'crawl_and_extract_signals' first.'"

    try:
        #Embed the query
        query_embedding = embedding_model.encode([query])
        query_embedding_np = np.array(query_embedding).astype("float32")

        #Search the vector space
        distances,  indices = index.search(query_embedding_np, top_k)

        retrieved_context = []
        for idx in indices[0]:
            if idx != -1 and idx < len(chunks_database):
                retrieved_context.append(chunks_database[idx])

        if not retrieved_context:
            return "No matching security logs or contexts found for your query."

        context_block = "\n---\n".join(retrieved_context)
        return f"=== RETRIEVED KNOWEDGE CONTEXT ===\n\n{context_block}"

    except Exception as e:
        return f"Error querying local RAG architecture: {str(e)}"

#=======================================
# 3. TOOL LAYER 2: GROUND TRUTH ENGINE
#=======================================

@mcp.tool()
def lookup_cve_ground_truth(cve_id: str) -> str:
    """
    Fetches real-time official vulnerability information from a public database for a specific CVE ID.
    Acts as the verification engine for hypotheses.
    """

    #Using the official Mitre CVE API endpoint
    url = f"https://cveawg.mitre.org/api/cve/{cve_id.upper()}"

    try:
        response = requests.get(url, timeout=7)
        if response.status_code == 200:
            data = response.json()
            
            # Navigate nested structure down to the public description
            descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [{}])
            summary_text = descriptions[0].get("value", "No detailed description text provided.")
            return f"=== GROUND TRUTH DATA FOR {cve_id.upper()} ===\nDescription: {summary_text}"

        elif response.status_code == 404:
            return f"CVE ID {cve_id} not found in the official database records."
            return f"GROUND TRUTH LOOKUP FAILED WITH HTTP STATUS CODE: {response.status_code}"

    except Exception as e:
          return f"Could not reach Ground Truth API: {str(e)}"

if __name__ == "__main__":
    mcp.run()