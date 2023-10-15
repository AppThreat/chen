"""Client for chen server"""
import asyncio
import json
import os
import platform
import tempfile

import httpx
import oras.client
import oras.provider
from oras.logger import setup_logger

setup_logger(quiet=True, debug=False)

UVLOOP_AVAILABLE = True
try:
    import uvloop
except Exception:
    UVLOOP_AVAILABLE = False
import websockets

from chenpy.utils import (
    check_labels_list,
    expand_search_str,
    fix_json,
    fix_query,
    parse_error,
    print_flows,
    print_md,
    print_table,
)

if platform.system() == "Windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
elif UVLOOP_AVAILABLE:
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


headers = {"Content-Type": "application/json", "Accept-Encoding": "gzip"}
CLIENT_TIMEOUT = os.getenv("HTTP_CLIENT_TIMEOUT")


class Connection:
    """
    Connection object to hold following connections:
       - Websocket to chen server
       - http connection to chen server
       - http connection to atomgen server
    """

    def __init__(self, atomgenclient, httpclient, websocket):
        self.atomgenclient = atomgenclient
        self.httpclient = httpclient
        self.websocket = websocket

    async def __aenter__(self):
        return self

    async def ping(self):
        """Send websocket ping message"""
        await self.websocket.ping()

    async def close(self):
        """Close all connections"""
        await self.atomgenclient.close()
        await self.httpclient.close()
        await self.websocket.close()

    async def __aexit__(self, exc_type, exc_value, exc_traceback):
        return await self.close()


def get_sync(
    base_url="http://localhost:9000",
    atomgen_url="http://localhost:7072",
    username=None,
    password=None,
):
    """Function to create a plain synchronous http connection to chen and atomgen server"""
    auth = None
    if username and password:
        auth = httpx.BasicAuth(username, password)
    base_url = base_url.rstrip("/")
    client = httpx.Client(base_url=base_url, auth=auth, timeout=CLIENT_TIMEOUT)
    atomgenclient = None
    if atomgen_url:
        atomgenclient = httpx.Client(base_url=atomgen_url, timeout=CLIENT_TIMEOUT)
    return Connection(atomgenclient, client, None)


async def get(
    base_url="http://localhost:8080",
    atomgen_url="http://localhost:7072",
    username=None,
    password=None,
):
    """Function to create a connection to chen and atomgen server"""
    auth = None
    if username and password:
        auth = httpx.BasicAuth(username, password)
    base_url = base_url.rstrip("/")
    client = httpx.AsyncClient(base_url=base_url, auth=auth, timeout=CLIENT_TIMEOUT)
    atomgenclient = None
    if atomgen_url:
        atomgenclient = httpx.AsyncClient(base_url=atomgen_url, timeout=CLIENT_TIMEOUT)
    ws_url = f"""{base_url.replace("http://", "ws://").replace("https://", "wss://")}/connect"""
    websocket = await websockets.connect(ws_url, ping_interval=None, ping_timeout=None)
    connected_msg = await websocket.recv()
    if connected_msg != "connected":
        raise websockets.exceptions.InvalidState(
            "Didn't receive connected message from chen server"
        )
    # Workaround to fix websockets.exceptions.ConnectionClosedError
    await asyncio.sleep(0)
    return Connection(atomgenclient, client, websocket)


async def send(connection, message):
    """Send message to the chen server via websocket"""
    await connection.websocket.send(message)


async def receive(connection):
    """Receive message from the chen server"""
    return await connection.websocket.recv()


async def p(connection, query_str, title="", caption="", sync=False):
    """Function to print the result as a table"""
    result = await query(connection, query_str, sync=sync)
    print_table(result, title, caption)
    return result


async def q(connection, query_str, sync=False):
    """Query chen server and optionally print the result as a table if the query ends with .p"""
    if query_str.strip().endswith(".p"):
        query_str = f"{query_str[:-2]}.toJsonPretty"
        return await p(connection, query_str, sync=sync)
    return await query(connection, query_str, sync=sync)


async def query(connection, query_str, sync=False):
    """Query chen server"""
    client = connection.httpclient
    if isinstance(client, httpx.AsyncClient):
        response = await client.post(
            url=f"/query{'-sync' if sync else ''}",
            headers=headers,
            json={"query": fix_query(query_str)},
        )
    else:
        sync = True
        response = client.post(
            url=f"/query{'-sync' if sync else ''}",
            headers=headers,
            json={"query": fix_query(query_str)},
        )
    if response.status_code == httpx.codes.OK:
        j = response.json()
        if sync:
            return fix_json(j.get("stdout", ""))
        res_uuid = j.get("uuid")
        try:
            completed_uuid = await receive(connection)
            if completed_uuid == res_uuid:
                response = await client.get(
                    url=f"/result/{completed_uuid}", headers=headers
                )
                if response.status_code == httpx.codes.OK:
                    j = response.json()
                    sout = j.get("stdout", "")
                    serr = j.get("stderr", "")
                    if sout:
                        return fix_json(sout)
                    return parse_error(serr)
        except Exception:
            return None
    return None


async def bulk_query(connection, query_list, sync=False):
    """Bulk query chen server"""
    client = connection.httpclient
    websocket = connection.websocket
    uuid_list = []
    response_list = []
    for query_str in query_list:
        if isinstance(client, httpx.AsyncClient):
            response = await client.post(
                url=f"/query{'-sync' if sync else ''}",
                headers=headers,
                json={"query": fix_query(query_str)},
            )
        else:
            sync = True
            response = client.post(
                url="/query-sync", headers=headers, json={"query": fix_query(query_str)}
            )
        if response.status_code == httpx.codes.OK:
            j = response.json()
            if sync:
                sout = j.get("stdout", "")
                serr = j.get("stderr", "")
                if sout:
                    response_list.append(fix_json(sout))
                else:
                    response_list.append({"error": parse_error(serr)})
            else:
                res_uuid = j.get("uuid")
                uuid_list.append(res_uuid)
    if sync:
        return response_list
    async for completed_uuid in websocket:
        if completed_uuid in uuid_list:
            response = await client.get(
                url=f"/result/{completed_uuid}", headers=headers
            )
            if response.status_code == httpx.codes.OK:
                j = response.json()
                sout = j.get("stdout", "")
                serr = j.get("stderr", "")
                if sout:
                    response_list.append(fix_json(sout))
                else:
                    response_list.append({"error": parse_error(serr)})
        if len(response_list) == len(uuid_list):
            return response_list
    return response_list


async def flows(connection, source, sink):
    """Execute reachableByFlows query"""
    return await flowsp(
        connection,
        source,
        sink,
        print_result=bool(os.getenv("POLYNOTE_VERSION")),
    )


async def flowsp(connection, source, sink, print_result=True):
    """Execute reachableByFlows query and optionally print the result table"""
    if not source.startswith("def"):
        source = f"def source = {source}"
    if not sink.startswith("def"):
        sink = f"def sink = {sink}"
    results = await bulk_query(
        connection,
        [
            source,
            sink,
            "sink.reachableByFlows(source).p",
        ],
    )
    if print_result and len(results):
        tmpres = results[-1]
        if isinstance(tmpres, dict) and tmpres.get("response"):
            tmpres = tmpres.get("response")
        tmpA = tmpres.split('"""')[1:-1]
        print_md("\n".join([n for n in tmpA if len(n.strip()) > 1]))
    return results


async def df(
    connection,
    source,
    sink,
    print_result=True if os.getenv("POLYNOTE_VERSION") else False,
    filter=None,
    check_labels=check_labels_list,
):
    """
    Execute reachableByFlows query. Optionally accepts filters which could be a raw conditional string or predefined keywords such as skip_control_structures, skip_cfg and skip_checks
    skip_control_structures: This adds a control structure filter `filter(m => m.elements.isControlStructure.size > 0)` to skip flows with control statements such if condition or break
    skip_cfg: This adds a cfg filter `filter(m => m.elements.isCfgNode.size > 0)` to skip flows with control flow graph nodes
    skip_checks: When used with check_labels parameter, this could filter flows containing known validation and sanitization code in the flow. Has a default list.
    """
    filter_str = ""
    if isinstance(check_labels, str):
        check_labels = check_labels.split("|")
    if isinstance(source, dict):
        for k, v in source.items():
            if k in ("parameter", "tag"):
                source = f"""atom.tag.name("{v}").{k}"""
            elif k in ("method", "call", "annotation"):
                source = f"""atom.{k}{expand_search_str(v)}"""
    if isinstance(sink, dict):
        for k, v in sink.items():
            if k in ("parameter", "tag"):
                sink = f"""atom.tag.name("{v}").{k}"""
            elif k in ("method", "call", "annotation"):
                sink = f"""atom.{k}{expand_search_str(v)}"""
    if not source.startswith("def"):
        source = f"def source = {source}"
    if not sink.startswith("def"):
        sink = f"def sink = {sink}"
    if filter:
        if isinstance(filter, str):
            if filter == "skip_checks":
                filter_str = f""".filter(m => m.elements.code(".*({'|'.join(check_labels)}).*").size == 0)"""
            elif not filter.startswith("."):
                filter_str = f".filter({filter})"
        elif isinstance(filter, list):
            for k in filter:
                if k == "skip_control_structures":
                    filter_str = f"{filter_str}.filter(m => m.elements.isControlStructure.size > 0)"
                elif k == "skip_cfg":
                    filter_str = (
                        f"{filter_str}.filter(m => m.elements.isCfgNode.size > 0)"
                    )
                elif k == "skip_checks":
                    filter_str = f"""{filter_str}.filter(m => m.elements.code(".*({'|'.join(check_labels)}).*").size == 0)"""
                else:
                    filter_str = f"""{filter_str}.filter({k})"""
    with tempfile.NamedTemporaryFile(
        prefix="reachable_flows_", suffix=".json", delete=False
    ) as fp:
        res = await bulk_query(
            connection,
            [
                source,
                sink,
                f'sink.reachableByFlows(source){filter_str}.map(m => (m, m.elements.location.l)).toJson |> "{fp.name}"',
            ],
        )
        try:
            results = json.load(fp)
            if print_result:
                print_flows(results)
        except json.JSONDecodeError:
            return res[-1] if len(res) else res
    return results


async def reachable_by_flows(connection, source, sink, print_result=False):
    """Execute reachableByFlows query"""
    return await df(connection, source, sink, print_result)


async def create_cpg(
    connection,
    src,
    out_dir=None,
    lang=None,
    slice=None,
    slice_mode="Usages",
    auto_build=True,
    skip_sbom=True,
):
    """Create Atom using atomgen server"""
    client = connection.atomgenclient
    if not client:
        return {
            "error": "true",
            "message": "No active connection to atomgen server. Pass the atomgen url to the client.get method.",
        }, 500
    # Suppor for url
    url = ""
    if src.startswith("http") or src.startswith("git://") or src.startswith("pkg:"):
        url = src
        src = ""
    data = {
        "src": src,
        "url": url,
        "out_dir": out_dir,
        "lang": lang,
        "slice": "true" if slice else "false",
        "slice_mode": slice_mode,
        "auto_build": "true" if auto_build else "false",
        "skip_sbom": "true" if skip_sbom else "false",
    }
    if isinstance(client, httpx.AsyncClient):
        response = await client.post(
            url="/cpg",
            headers=headers,
            json=data,
        )
    else:
        response = client.post(
            url="/cpg",
            headers=headers,
            json=data,
        )
    return response.json()


async def graphml_export(connection, filter_str="method"):
    """Method to export method as graphml"""
    with tempfile.NamedTemporaryFile(
        prefix="graphml_export_", suffix=".graphml", delete=False
    ) as fp:
        res = await bulk_query(
            connection,
            [
                """
import overflowdb.formats.ExportResult
import overflowdb.formats.graphml.GraphMLExporter
import java.nio.file.{Path, Paths}

case class MethodSubGraph(methodName: String, nodes: Set[Node]) {
  def edges: Set[Edge] = {
    for {
      node <- nodes
      edge <- node.bothE.asScala
      if nodes.contains(edge.inNode) && nodes.contains(edge.outNode)
    } yield edge
  }
}

def plus(resultA: ExportResult, resultB: ExportResult): ExportResult = {
  ExportResult(
    nodeCount = resultA.nodeCount + resultB.nodeCount,
    edgeCount = resultA.edgeCount + resultB.edgeCount,
    files = resultA.files ++ resultB.files,
    additionalInfo = resultA.additionalInfo
  )
}

def splitByMethod(cpg: Cpg): IterableOnce[MethodSubGraph] = {
  atom.%(filter_str)s.map { method =>
    MethodSubGraph(methodName = method.name, nodes = method.ast.toSet)
  }
}
"""
                % dict(filter_str=filter_str),
                """
({splitByMethod(cpg).iterator
  .map { case subGraph @ MethodSubGraph(methodName, nodes) =>
    GraphMLExporter.runExport(nodes, subGraph.edges, Paths.get("%(gml_file)s"))
  }
  .reduce(plus)
})
"""
                % dict(gml_file=fp.name),
            ],
        )
        return fp.name


class ChenDistributionRegistry(oras.provider.Registry):
    def get_manifest(self, container, allowed_media_type=None):
        """
        Retrieve a manifest for a package.

        :param container:  parsed container URI
        :type container: oras.container.Container or str
        :param allowed_media_type: one or more allowed media types
        :type allowed_media_type: str
        """
        if not allowed_media_type:
            allowed_media_type = [oras.defaults.default_manifest_media_type]
        headers = {"Accept": ";".join(allowed_media_type)}

        get_manifest = f"{self.prefix}://{container.manifest_url()}"  # type: ignore
        response = self.do_request(get_manifest, "GET", headers=headers)
        self._check_200_response(response)
        manifest = response.json()
        return manifest
