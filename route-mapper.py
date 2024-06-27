import networkx as nx
import plotly.graph_objects as go
from scapy.all import *
from collections import defaultdict
import ipaddress
import sys

# Perform ICMP traceroute
def icmp_traceroute(dest_ip):
    result = []
    for ttl in range(1, 30):
        pkt = IP(dst=dest_ip, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=1)
        if reply is None:
            result.append('*')
            continue
        result.append(reply.src)
        if reply.type == 0:  # Echo reply
            break
    return result

# Get range of IPs from command line arguments
def get_ip_range(start_ip, end_ip):
    start_ip = ipaddress.ip_address(start_ip)
    end_ip = ipaddress.ip_address(end_ip)
    return [str(ip) for ip in ipaddress.summarize_address_range(start_ip, end_ip)]

# Validate command line arguments
if len(sys.argv) != 3:
    print("Usage: python route-mapper.py <start_ip> <end_ip>")
    sys.exit(1)

start_ip = sys.argv[1]
end_ip = sys.argv[2]

# Generate list of IPs in the specified range
ip_list = get_ip_range(start_ip, end_ip)

# Perform traceroute for each IP
routes = {}
for ip in ip_list:
    routes[ip] = icmp_traceroute(ip)

# Create a graph from the traceroute results
G = nx.Graph()

# Add edges to the graph
for ip, route in routes.items():
    for i in range(len(route) - 1):
        if route[i] != '*' and route[i + 1] != '*':
            G.add_edge(route[i], route[i + 1], target=ip)

# Define a position layout for nodes
pos = nx.spring_layout(G)

# Create the plot
edge_trace = []
for edge in G.edges(data=True):
    x0, y0 = pos[edge[0]]
    x1, y1 = pos[edge[1]]
    edge_trace.append(go.Scatter(x=[x0, x1], y=[y0, y1],
                                 line=dict(width=0.5, color='#888'),
                                 hoverinfo='none',
                                 mode='lines'))

node_trace = go.Scatter(
    x=[],
    y=[],
    text=[],
    mode='markers+text',
    hoverinfo='text',
    marker=dict(
        showscale=True,
        colorscale='YlGnBu',
        color=[],
        size=10,
        colorbar=dict(
            thickness=15,
            title='Router',
            xanchor='left',
            titleside='right'
        )
    )
)

for node in G.nodes():
    x, y = pos[node]
    node_trace['x'] += (x,)
    node_trace['y'] += (y,)

for node, adjacencies in enumerate(G.adjacency()):
    node_trace['marker']['color'] += (len(adjacencies[1]),)
    node_info = f'{adjacencies[0]} ({len(adjacencies[1])} connections)'
    node_trace['text'] += (node_info,)

# Check for deviations from the usual path
usual_path = None
deviations = defaultdict(list)

for ip, route in routes.items():
    if usual_path is None:
        usual_path = route
    else:
        for i in range(min(len(route), len(usual_path))):
            if route[i] != usual_path[i]:
                deviations[ip].append(route[i])

# Highlight deviations in the plot
for ip, deviation_points in deviations.items():
    for point in deviation_points:
        if point in pos:
            x, y = pos[point]
            node_trace['x'] += (x,)
            node_trace['y'] += (y,)
            node_trace['text'] += (f'Deviation at {point} for {ip}',)
            node_trace['marker']['color'] += (len(deviation_points),)

fig = go.Figure(data=edge_trace + [node_trace],
                layout=go.Layout(
                    title='<br>Network Graph of Traceroutes',
                    titlefont_size=16,
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=20, l=5, r=5, t=40),
                    annotations=[dict(
                        text="Traceroute visualization",
                        showarrow=False,
                        xref="paper", yref="paper")],
                    xaxis=dict(showgrid=False, zeroline=False),
                    yaxis=dict(showgrid=False, zeroline=False)))

# Save to HTML
fig.write_html("route-mapper.html")

print("Graph has been saved to route_mapper.html")
