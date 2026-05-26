import asyncio
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def run_test():
    print("--- TEST CLIENT STARTING ---")
    
    # Configure the server parameters
    server_params = StdioServerParameters(
        command=r"C:\Users\Dell\Documents\mini_cyber_scanner\venv\Scripts\python.exe",
        args=[r"C:\Users\Dell\Documents\mini_cyber_scanner\cyber_scan_server.py"],
        env=None
    )

    print("Connecting to Cyber Security Scanner Server...")
    
    try:
        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                # Initialize connection
                await session.initialize()
                print("✓ Connected successfully!\n")

                # List tools
                print("--- Querying Server Tools ---")
                tools_response = await session.list_tools()
                for tool in tools_response.tools:
                    print(f"Tool Found: {tool.name}")
                
                # ========================================================
                # TEST 1: Crawl & Populate RAG Knowledge Base
                # ========================================================
                print("\n--- Testing Tool 1: crawl_and_extract_signals ---")
                test_args = {"url": "https://peps.python.org/pep-0514/"}
                result = await session.call_tool("crawl_and_extract_signals", arguments=test_args)
                print("\n[Server Response]:")
                print(result.content[0].text)
                
                # ========================================================
                # TEST 2: Query the FAISS Vector Database (Semantic Search)
                # ========================================================
                print("\n--- Testing Tool 2: query_knowledge_layer ---")
                # Looking up data related to the Windows registry from the crawled PEP 514 content
                query_args = {"query": "Windows registry key configuration string", "top_k": 2}
                query_result = await session.call_tool("query_knowledge_layer", arguments=query_args)
                print("\n[Server Search Response]:")
                print(query_result.content[0].text)

                # ========================================================
                # TEST 3: External Live CVE Ground Truth Verification
                # ========================================================
                print("\n--- Testing Tool 3: lookup_cve_ground_truth ---")
                # Using a well-known vulnerability ID (Log4Shell) as a verification test
                cve_args = {"cve_id": "CVE-2021-44228"}
                cve_result = await session.call_tool("lookup_cve_ground_truth", arguments=cve_args)
                print("\n[Server CVE Response]:")
                print(cve_result.content[0].text)
                    
    except Exception as e:
        print(f"An error occurred during client execution: {e}", file=sys.stderr)

    print("\n--- TEST CLIENT FINISHED ---")

if __name__ == "__main__":
    asyncio.run(run_test())