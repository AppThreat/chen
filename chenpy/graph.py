"""
Module to work with networkx graph data
"""
import json
import tempfile
from collections import Counter, defaultdict

from chenpy.utils import calculate_hash

DATABASE_PACK_AVAILABLE = True
SCIENCE_PACK_AVAILABLE = True
try:
    import networkx as nx
    from networkx.readwrite import json_graph, read_graphml
except ImportError:
    DATABASE_PACK_AVAILABLE = False

try:
    import torch
    from torch import Tensor
    from torch_geometric.data import Data
    from torchtext.data.functional import (
        generate_sp_model,
        load_sp_model,
        sentencepiece_numericalizer,
        sentencepiece_tokenizer,
    )
except ImportError:
    SCIENCE_PACK_AVAILABLE = False


def _hash_label(label, digest_size):
    return calculate_hash(label, digest_size=digest_size)


def _init_node_labels(G, edge_attr_fn, node_attr_fn):
    if node_attr_fn:
        return {u: node_attr_fn(dd) for u, dd in G.nodes(data=True)}
    elif edge_attr_fn:
        return {u: "" for u in G}
    else:
        return {u: str(deg) for u, deg in G.degree()}


def _neighborhood_aggregate(G, node, node_labels, edge_attr_fn=None):
    """
    Compute new labels for given node by aggregating
    the labels of each node's neighbors.
    """
    label_list = []
    for nbr in G.neighbors(node):
        prefix = "" if edge_attr_fn is None else edge_attr_fn(G[node][nbr])
        label_list.append(prefix + node_labels[nbr])
    return node_labels[node] + "".join(sorted(label_list))


def graph_hash(G, edge_attr_fn=None, node_attr_fn=None, iterations=3, digest_size=16):
    """Return Weisfeiler Lehman (WL) graph hash"""

    def weisfeiler_lehman_step(G, labels, edge_attr_fn=None):
        """
        Apply neighborhood aggregation to each node
        in the graph.
        Computes a dictionary with labels for each node.
        """
        new_labels = {}
        for node in G.nodes():
            label = _neighborhood_aggregate(G, node, labels, edge_attr_fn=edge_attr_fn)
            new_labels[node] = _hash_label(label, digest_size)
        return new_labels

    # set initial node labels
    node_labels = _init_node_labels(G, edge_attr_fn, node_attr_fn)

    subgraph_hash_counts = []
    for _ in range(iterations):
        node_labels = weisfeiler_lehman_step(G, node_labels, edge_attr_fn=edge_attr_fn)
        counter = Counter(node_labels.values())
        # sort the counter, extend total counts
        subgraph_hash_counts.extend(sorted(counter.items(), key=lambda x: x[0]))

    # hash the final counter
    return _hash_label(str(tuple(subgraph_hash_counts)), digest_size)


def subgraph_hashes(
    G, edge_attr_fn=None, node_attr_fn=None, iterations=3, digest_size=16
):
    """Return a dictionary of subgraph hashes by node."""

    def weisfeiler_lehman_step(G, labels, node_subgraph_hashes, edge_attr_fn=None):
        """
        Apply neighborhood aggregation to each node
        in the graph.
        Computes a dictionary with labels for each node.
        Appends the new hashed label to the dictionary of subgraph hashes
        originating from and indexed by each node in G
        """
        new_labels = {}
        for node in G.nodes():
            label = _neighborhood_aggregate(G, node, labels, edge_attr_fn=edge_attr_fn)
            hashed_label = _hash_label(label, digest_size)
            new_labels[node] = hashed_label
            node_subgraph_hashes[node].append(hashed_label)
        return new_labels

    node_labels = _init_node_labels(G, edge_attr_fn, node_attr_fn)

    node_subgraph_hashes = defaultdict(list)
    for _ in range(iterations):
        node_labels = weisfeiler_lehman_step(
            G, node_labels, node_subgraph_hashes, edge_attr_fn
        )

    return dict(node_subgraph_hashes)


def diff(first_graph, second_graph, include_common=False, as_dict=False, as_dot=False):
    """Function to compute the difference between two graphs"""
    return diff_graph(
        first_graph,
        second_graph,
        include_common=include_common,
        as_dict=as_dict,
        as_dot=as_dot,
    )


def get_node_label(n):
    """Retrieve a label for the node from various data attributes"""
    if not n:
        return ""
    for at in (
        "label",
        "CODE",
        "SIGNATURE",
        "METHOD_FULL_NAME",
        "NAME",
        "VARIABLE",
        "labelE",
    ):
        if n.get(at) is not None:
            return n.get(at)
    return ""


def diff_graph(
    first_graph, second_graph, include_common=False, as_dict=False, as_dot=False
):
    """Function to compute the difference between two graphs and optionally convert the result to dict or dot format"""
    if not first_graph and second_graph:
        return second_graph
    if first_graph and not second_graph:
        return first_graph
    graph = nx.Graph()
    if not first_graph and not second_graph:
        return graph
    first_graph_nodes = [get_node_label(r[1]) for r in first_graph.nodes(data=True)]
    second_graph_nodes = [get_node_label(r[1]) for r in second_graph.nodes(data=True)]
    removed_nodes = set(first_graph_nodes) - set(second_graph_nodes)
    added_nodes = set(second_graph_nodes) - set(first_graph_nodes)
    nodes = set(second_graph_nodes) & set(first_graph_nodes)
    first_graph_edges = [
        (r[0], r[1], get_node_label(r[2])) for r in first_graph.edges(data=True)
    ]
    second_graph_edges = [
        (r[0], r[1], get_node_label(r[2])) for r in second_graph.edges(data=True)
    ]
    removed_edges = set(first_graph_edges) - set(second_graph_edges)
    removed_edges_fmt = []
    for removed_edge in removed_edges:
        src = removed_edge[0]
        dest = removed_edge[1]
        if removed_edge[0] in removed_nodes:
            src = "-" + removed_edge[0]
        if removed_edge[1] in removed_nodes:
            dest = "-" + removed_edge[1]
        removed_edges_fmt.append((src, dest, removed_edge[2]))
    added_edges = set(second_graph_edges) - set(first_graph_edges)
    added_edges_fmt = []
    for added_edge in added_edges:
        src = added_edge[0]
        dest = added_edge[1]
        if added_edge[0] in added_nodes:
            src = "+" + added_edge[0]
        if added_edge[1] in added_nodes:
            dest = "+" + added_edge[1]
        added_edges_fmt.append((src, dest, added_edge[2]))
    edges = set(second_graph_edges) & set(first_graph_edges)
    for removed_node in removed_nodes:
        graph.add_node("-" + removed_node)
    for added_node in added_nodes:
        graph.add_node("+" + added_node)
    if include_common:
        for node in nodes:
            graph.add_node(node)
    for removed_edge in removed_edges_fmt:
        graph.add_edge(removed_edge[0], removed_edge[1], label="-" + removed_edge[2])
    for added_edge in added_edges_fmt:
        graph.add_edge(added_edge[0], added_edge[1], label="+" + added_edge[2])
    if include_common:
        for edge in edges:
            graph.add_edge(edge[0], edge[1], label=edge[2])
    if as_dict:
        return nx.to_dict_of_dicts(graph)
    if as_dot:
        with tempfile.NamedTemporaryFile(
            prefix="diff_graph", suffix=".dot", delete=False
        ) as fp:
            write_dot(graph, fp.name)
            fp.flush()
            return fp.read().decode()
    return graph


def node_match_fn(n1, n2):
    return get_node_label(n1) == get_node_label(n2)


def gep(first_graph, second_graph, upper_bound=500):
    distance = nx.optimal_edit_paths(
        first_graph,
        second_graph,
        node_match=node_match_fn,
        edge_match=node_match_fn,
        upper_bound=upper_bound,
    )
    if distance is None:
        distance = -1
    return distance


def ged(first_graph, second_graph, timeout=5, upper_bound=500):
    distance = nx.graph_edit_distance(
        first_graph,
        second_graph,
        node_match=node_match_fn,
        edge_match=node_match_fn,
        timeout=timeout,
        upper_bound=upper_bound,
    )
    if distance is None:
        distance = -1
    return distance


def write_dot(G, path):
    """Function to export graph as dot"""
    nx.nx_agraph.write_dot(G, path)


def hash(
    G,
    subgraph=False,
    edge_attr_fn=get_node_label,
    node_attr_fn=get_node_label,
    iterations=3,
    digest_size=16,
):
    """Function to compute the hashes for a graph using Weisfeiler Lehman hashing algorithm"""
    if subgraph:
        return subgraph_hashes(
            G,
            edge_attr_fn=edge_attr_fn,
            node_attr_fn=node_attr_fn,
            iterations=iterations,
            digest_size=digest_size,
        )
    return graph_hash(
        G,
        edge_attr_fn=edge_attr_fn,
        node_attr_fn=node_attr_fn,
        iterations=iterations,
        digest_size=digest_size,
    )


def summarize(G, as_dict=False, as_dot=False):
    """Function to summarize the graph based on node labels"""
    summary_graph = nx.snap_aggregation(
        G, node_attributes=("label", "CODE"), edge_attributes=("label", "CODE")
    )
    if as_dict:
        return nx.to_dict_of_dicts(summary_graph)
    if as_dot:
        with tempfile.NamedTemporaryFile(
            prefix="summary_graph", suffix=".dot", delete=False
        ) as fp:
            write_dot(summary_graph, fp.name)
            fp.flush()
            return fp.read().decode()
    return summary_graph


def is_similar(M1, M2, edit_distance=10, upper_bound=500, timeout=5):
    if not diff_graph(M1, M2, as_dict=True):
        return True
    distance = ged(M1, M2, upper_bound=upper_bound, timeout=timeout)
    if distance == -1:
        return False
    return int(distance) < edit_distance


def convert_graphml(
    gml_file, force_multigraph=False, as_graph=True, as_adjacency_data=False
):
    """Function to convert graphml to networkx"""
    if not DATABASE_PACK_AVAILABLE:
        return RuntimeError(
            "Graph database dependencies missing. Please refer to the documentation to install the database pack or use the official chen container image."
        )
    try:
        G = read_graphml(gml_file, force_multigraph=force_multigraph)
        if as_graph:
            return G
        if as_adjacency_data:
            return json.dumps(json_graph.adjacency_data(G))
    except Exception:
        return None


def to_pyg(
    G,
    group_node_attrs=None,
    group_edge_attrs=None,
):
    """Converts a :obj:`networkx.Graph` or :obj:`networkx.DiGraph` to a
    :class:`torch_geometric.data.Data` instance."""
    if not SCIENCE_PACK_AVAILABLE:
        return RuntimeError(
            "Scientific dependencies missing. Please refer to the documentation to install the science pack or use the official chen container image."
        )
    G = G.to_directed() if not nx.is_directed(G) else G

    mapping = dict(zip(G.nodes(), range(G.number_of_nodes())))
    edge_index = torch.empty((2, G.number_of_edges()), dtype=torch.long)
    for i, (src, dst) in enumerate(G.edges()):
        edge_index[0, i] = mapping[src]
        edge_index[1, i] = mapping[dst]

    data = defaultdict(list)

    if G.number_of_nodes() > 0:
        node_attrs = list(next(iter(G.nodes(data=True)))[-1].keys())
    else:
        node_attrs = {}

    if G.number_of_edges() > 0:
        edge_attrs = list(next(iter(G.edges(data=True)))[-1].keys())
    else:
        edge_attrs = {}

    for i, (_, feat_dict) in enumerate(G.nodes(data=True)):
        for key, value in feat_dict.items():
            data[str(key)].append(value)

    for i, (_, _, feat_dict) in enumerate(G.edges(data=True)):
        for key, value in feat_dict.items():
            key = f"edge_{key}" if key in node_attrs else key
            data[str(key)].append(value)

    for key, value in G.graph.items():
        if key == "node_default" or key == "edge_default":
            continue  # Do not load default attributes.
        key = f"graph_{key}" if key in node_attrs else key
        data[str(key)] = value

    for key, value in data.items():
        if isinstance(value, (tuple, list)) and isinstance(value[0], Tensor):
            data[key] = torch.stack(value, dim=0)
        else:
            try:
                data[key] = torch.tensor(value)
            except (ValueError, TypeError):
                pass

    data["edge_index"] = edge_index.view(2, -1)
    data = Data.from_dict(data)

    if group_node_attrs is all:
        group_node_attrs = list(node_attrs)
    if group_node_attrs is not None:
        xs = []
        for key in group_node_attrs:
            x = data.get(key, "")
            x = x.view(-1, 1) if x.dim() <= 1 else x
            xs.append(x)
            if data.get(key) is not None:
                del data[key]
        data.x = torch.cat(xs, dim=-1)

    if group_edge_attrs is all:
        group_edge_attrs = list(edge_attrs)
    if group_edge_attrs is not None:
        xs = []
        for key in group_edge_attrs:
            key = f"edge_{key}" if key in node_attrs else key
            x = data.get(key, "")
            x = x.view(-1, 1) if x.dim() <= 1 else x
            xs.append(x)
            if data.get(key) is not None:
                del data[key]
        data.edge_attr = torch.cat(xs, dim=-1)

    if data.x is None and data.pos is None:
        data.num_nodes = G.number_of_nodes()

    return data
