import asyncio
import os
import json
import re
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Define dedicated folder for structural security output profiles
OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Point the client directly to your local virtual environment's Python binary
# This prevents it from accidentally picking up the global system Python 3.14
venv_python = os.path.abspath(os.path.join(".venv", "Scripts", "python.exe"))

server_params = StdioServerParameters(
    command=venv_python,
    args=["cyber_scan_server.py"]
)

def clean_json_string(raw_text: str) -> str:
    """
    Cleans markdown formatting blocks (like ```json ... ```) which often 
    cause JSON parsing errors with local Small Language Models.
    """
    cleaned = raw_text.strip()
    # Remove markdown code blocks if present
    cleaned = re.sub(r"^```json\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^```\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()

async def main():
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize connection
            await session.initialize()
            
            # ==========================================================
            # 1. TOOL DISCOVERY LAYER
            # ==========================================================
            print("\n--- 🔍 Discovering Available MCP Tools ---")
            tools_response = await session.list_tools()
            for tool in tools_response.tools:
                print(f"Found Registered Tool: {tool.name}")
                
            # ==========================================================
            # 2. STEP 1: EXECUTE SMART CRAWLER & SAVE METRICS
            # ==========================================================
            print("\n--- 🌐 Step 1: Running Smart Web Crawler ---")
            target_url = "https://httpbin.org" 
            print(f"Targeting URL for security signals: {target_url}")
            
            crawl_response = await session.call_tool(
                "crawl_and_extract_signals", 
                arguments={"url": target_url}
            )
            crawl_raw_text = crawl_response.content[0].text
            
            try:
                crawl_json = json.loads(crawl_raw_text)
                print(json.dumps(crawl_json, indent=2))
                
                output_path = os.path.join(OUTPUT_DIR, "crawler_output.json")
                with open(output_path, "w") as f:
                    json.dump(crawl_json, f, indent=4)
                print(f"💾 Saved structured crawler format to {output_path}")
            except json.JSONDecodeError:
                print("⚠️ Crawler output was not valid JSON. Printing raw response:")
                print(crawl_raw_text)

            # ==========================================================
            # 3. STEP 2: QUERY VECTOR DATABASE & SAVE SEARCH MATRICES
            # ==========================================================
            print("\n--- 🧠 Step 2: Querying In-Memory FAISS Vector Database ---")
            search_query = "vulnerability or security signals"
            print(f"Executing semantic search for: '{search_query}'")
            
            rag_response = await session.call_tool(
                "query_knowledge_layer", 
                arguments={"query": search_query, "top_k": 2}
            )
            rag_raw_text = rag_response.content[0].text
            
            try:
                rag_json = json.loads(rag_raw_text)
                print(json.dumps(rag_json, indent=2))
                
                output_path = os.path.join(OUTPUT_DIR, "retrieval_output.json")
                with open(output_path, "w") as f:
                    json.dump(rag_json, f, indent=4)
                print(f"💾 Saved retrieval structure context matrix to {output_path}")
            except json.JSONDecodeError:
                print("⚠️ RAG database output was not valid JSON. Printing raw response:")
                print(rag_raw_text)

            # ==========================================================
            # 4. STEP 3: FETCH GROUND TRUTH DATA FOR A SPECIFIC CVE
            # ==========================================================
            print("\n--- 🛡️ Step 3: Fetching Official CVE Ground Truth ---")
            target_cve = "CVE-2024-3094" 
            print(f"Querying Mitre API for: {target_cve}")
            
            cve_response = await session.call_tool(
                "lookup_cve_ground_truth", 
                arguments={"cve_id": target_cve}
            )
            print(cve_response.content[0].text)

            # ==========================================================
            # 5. STEP 4: GENERATE ATTACK VECTOR GRAPH MATRIX
            # ==========================================================
            print("\n--- 📊 Step 4: Generating Network Attack Vector Graph Data ---")
            graph_response = await session.call_tool(
                "generate_attack_graph", 
                arguments={"target_url": target_url}
            )
            graph_raw_text = graph_response.content[0].text
            
            try:
                graph_json = json.loads(graph_raw_text)
                print(json.dumps(graph_json, indent=2))
                
                output_path = os.path.join(OUTPUT_DIR, "graph_output.json")
                with open(output_path, "w") as f:
                    json.dump(graph_json, f, indent=4)
                print(f"💾 Saved graph definition matrix directly to: {output_path}")
            except json.JSONDecodeError:
                print("⚠️ Graph definition schema parsing failed. Printing raw response:")
                print(graph_raw_text)

            # ==========================================================
            # 6. STEP 5: RUN LOCAL SLM SECURITY ANALYTICS ENGINE
            # ==========================================================
            print("\n--- 🤖 Step 5: Invoking Local SLM Intelligence Agent ---")
            
            cve_context = cve_response.content[0].text
            composite_scan_logs = (
                f"ALERT: System scan flagged a match for structural risk.\n"
                f"Context details:\n{cve_context}\n"
                f"Please provide an impact analysis evaluation."
            )
            
            slm_response = await session.call_tool(
                "analyze_vulnerability_with_slm", 
                arguments={"scan_results": composite_scan_logs}
            )
            slm_raw_text = slm_response.content[0].text
            
            cleaned_slm_text = clean_json_string(slm_raw_text)
            final_output_path = os.path.join(OUTPUT_DIR, "final_context_package.json")
            
            try:
                slm_json = json.loads(cleaned_slm_text)
                print(json.dumps(slm_json, indent=2))
                
                with open(final_output_path, "w") as f:
                    json.dump(slm_json, f, indent=4)
                print(f"💾 Saved final context package analysis matrix to {final_output_path}")
            except json.JSONDecodeError:
                print("⚠️ SLM Agent output was not raw JSON. Saving raw text as fallback...")
                fallback_data = {
                    "raw_unstructured_response": slm_raw_text,
                    "parsing_error": "Model response was not cleanly formattable as standard JSON structures"
                }
                with open(final_output_path, "w") as f:
                    json.dump(fallback_data, f, indent=4)
                print(f"💾 Saved raw SLM backup package to {final_output_path}")

if __name__ == "__main__":
    asyncio.run(main())