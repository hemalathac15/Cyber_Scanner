import os
import sys
import json

#========================================================================
# LIBRARY SAFETY CHECK (Auto-installs dependencies if missing)
#========================================================================
try:
    import networkx as nx
    import matplotlib.pyplot as plt
except ImportError:
    print("\n[!] Missing visualization dependencies. Installing 'networkx' and 'matplotlib'...", file=sys.stderr)
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "networkx", "matplotlib"])
    import networkx as nx
    import matplotlib.pyplot as plt

def render_cyber_graph():
    json_path = os.path.join("outputs", "graph_output.json")
    output_image_path = os.path.join("outputs", "attack_vector_graph.png")
    
    # Ensure outputs folder exists
    os.makedirs("outputs", exist_ok=True)
    
    if not os.path.exists(json_path):
        print(f"❌ Error: '{json_path}' not found. Run your 'test_mcp_client.py' pipeline first!", file=sys.stderr)
        return

    try:
        with open(json_path, "r") as f:
            graph_data = json.load(f)
    except Exception as e:
        print(f"❌ Error reading JSON file: {str(e)}", file=sys.stderr)
        return

    G = nx.DiGraph()

    # Dark Cyber Theme Color Variables
    BG_COLOR = "#0D1117"       # Obsidian background
    ROOT_COLOR = "#7952B3"     # Purple for root domain
    PAGE_COLOR = "#1F6FEB"     # Blue for pages
    API_COLOR = "#FF3366"      # Crimson for APIs
    EDGE_COLOR = "#58A6FF"     # Neon blue arrows
    TEXT_COLOR = "#F0F6FC"     # Clean white text

    color_map = []
    labels = {}
    
    for node in graph_data.get("nodes", []):
        n_id = node["id"]
        n_type = node.get("type", "page").lower()
        n_url = node.get("url", "")
        
        G.add_node(n_id)
        labels[n_id] = f"{n_url}\n[{n_type.upper()}]"
        
        # Dynamically color nodes based on their specialized types
        if n_type == "domain":
            color_map.append(ROOT_COLOR)
        elif n_type == "api":
            color_map.append(API_COLOR)
        else:
            color_map.append(PAGE_COLOR)

    for edge in graph_data.get("edges", []):
        G.add_edge(edge["source"], edge["target"], label=edge.get("type", "connects"))

    fig, ax = plt.subplots(figsize=(12, 8))
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)

    # Use a layout style that scales beautifully based on node counts
    pos = nx.spring_layout(G, k=1.5, seed=42)

    nx.draw_networkx_nodes(G, pos, node_color=color_map, node_size=3500, edgecolors="#ffffff", linewidths=1.2, ax=ax)
    nx.draw_networkx_edges(G, pos, edgelist=G.edges(), edge_color=EDGE_COLOR, width=2.0, arrowstyle="-|>", arrowsize=22, ax=ax)

    # Label positioning configuration
    for node_id, (x, y) in pos.items():
        plt.text(x, y, labels[node_id], color=TEXT_COLOR, fontsize=8, fontweight="bold",
                 horizontalalignment="center", verticalalignment="center",
                 bbox=dict(boxstyle="round,pad=0.4", fc=BG_COLOR, ec=EDGE_COLOR, alpha=0.9, lw=1))

    edge_labels = nx.get_edge_attributes(G, "label")
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7, font_color="#8B949E",
                                 bbox=dict(boxstyle="round,pad=0.2", fc=BG_COLOR, ec="none", alpha=0.8), ax=ax)

    ax.set_title("DYNAMIC INFRASTRUCTURE RECONNAISSANCE ATTACK SURFACE PATHWAY", color="#58A6FF", fontsize=13, fontweight="bold", pad=20)
    ax.axis("off")
    plt.tight_layout()
    
    try:
        plt.savefig(output_image_path, facecolor=fig.get_facecolor(), edgecolor='none', dpi=300)
        print(f"🎨 Beautiful dynamic graph updated successfully at: .\\{output_image_path}")
    except Exception as e:
        print(f"❌ Failed to write image to disk: {str(e)}", file=sys.stderr)
    finally:
        plt.close()

if __name__ == "__main__":
    render_cyber_graph()