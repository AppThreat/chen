"""
Function to detect files, methods and patterns that are common across languages
"""
from chenpy import client, graph
from chenpy.utils import colorize_dot_data, expand_search_str


async def list_files(connection, search_descriptor=None):
    """Retrieve the list files in the Atom"""
    search_str = expand_search_str(search_descriptor)
    return await client.q(connection, f"atom.file{search_str}")


async def list_annotations(connection):
    """Retrieve the annotations"""
    return await client.q(connection, "atom.annotation")


async def list_arguments(connection):
    """Retrieve the arguments"""
    return await client.q(connection, "atom.argument")


async def list_assignments(connection):
    """Retrieve all assignment operations"""
    return await client.q(connection, "atom.assignment")


async def list_calls(connection, search_descriptor=None):
    """Retrieve the method calls"""
    search_str = expand_search_str(search_descriptor)
    return await client.q(connection, f"atom.call{search_str}")


async def list_config_files(connection):
    """Retrieve the config files"""
    return await client.q(connection, "atom.configFile")


async def list_control_structures(connection):
    """Retrieve the control structures"""
    return await client.q(connection, "atom.controlStructure")


async def list_dependencies(connection):
    """Retrieve the dependency nodes"""
    return await client.q(connection, "atom.dependency")


async def list_identifiers(connection):
    """Retrieve the identifiers"""
    return await client.q(connection, "atom.identifier")


async def list_declared_identifiers(connection):
    """Retrieve the declared identifiers"""
    return await client.q(
        connection,
        """({atom.assignment.argument(1).isIdentifier.refsTo ++ atom.parameter.filter(_.typeFullName != "ANY")})""",
    )


async def list_imports(connection):
    """Retrieve the import statements"""
    return await client.q(connection, "atom.imports")


async def list_if_blocks(connection):
    """Retrieve the if blocks"""
    return await client.q(connection, "atom.ifBlock")


async def list_literals(connection):
    """Retrieve the literals"""
    return await client.q(connection, "atom.literal")


async def list_sensitive_literals(
    connection, pattern="(secret|password|token|key|admin|root)"
):
    """
    Function to list sensitive literals
    """
    return await client.q(
        connection,
        f'atom.call.assignment.where(_.argument.order(1).code("(?i).*{pattern}.*")).argument.order(2).isLiteral.location',
    )


async def list_locals(connection):
    """Retrieve the local variables"""
    return await client.q(connection, "atom.local")


async def list_members(connection):
    """Retrieve the member variables"""
    return await client.q(connection, "atom.member")


async def list_metadatas(connection):
    """Retrieve the metadata block"""
    return await client.q(connection, "atom.metaData")


async def nx(connection, method, graph_repr="cpg14"):
    """Retrieve the methods as a networkx object"""
    return await list_methods(
        connection, search_descriptor=method, as_graph=True, graph_repr=graph_repr
    )


async def get_method(connection, method, as_graph=False, graph_repr="pdg"):
    """Retrieve the method optionally converting to networkx format"""
    return await list_methods(
        connection, search_descriptor=method, as_graph=as_graph, graph_repr=graph_repr
    )


async def is_similar(connection, M1, M2, upper_bound=500, timeout=5):
    """Convenient method to check if two methods are similar using graph edit distance"""
    m1g = await get_method(connection, M1, as_graph=True)
    m2g = await get_method(connection, M2, as_graph=True)
    if not m1g or not m2g:
        return False
    return graph.is_similar(m1g, m2g, upper_bound=upper_bound, timeout=timeout)


async def list_methods(
    connection,
    search_descriptor=None,
    skip_operators=True,
    as_graph=False,
    graph_repr="pdg",
):
    """Function to filter and retrieve a list of methods"""
    if as_graph:
        return await export(
            connection,
            method=search_descriptor,
            export_repr=graph_repr,
            as_graph=as_graph,
        )
    else:
        search_str = expand_search_str(search_descriptor)
        filter_str = ""
        if skip_operators:
            filter_str = '.whereNot(_.name(".*<(operator|init)>.*"))'
        return await client.q(connection, f"""atom.method{search_str}{filter_str}""")


async def list_constructors(connection):
    """Retrieve the list of constructors"""
    return await client.q(connection, """atom.method.internal.name("<init>")""")


async def list_external_methods(connection):
    """Retrieve the external methods"""
    return await client.q(
        connection,
        """atom.method.external.whereNot(_.name(".*<operator|init>.*"))""",
    )


async def list_method_refs(connection):
    """Retrieve the method references"""
    return await client.q(connection, "atom.methodRef")


async def list_methodReturns(connection):
    """Retrieve the method return values"""
    return await client.q(connection, "atom.methodReturn")


async def list_namespaces(connection):
    """Retrieve the list of namespaces"""
    return await client.q(connection, "atom.namespace")


async def list_parameters(connection):
    """Retrieve the list of parameters"""
    return await client.q(connection, "atom.parameter")


async def list_tags(
    connection,
    name=None,
    value=None,
    is_call=False,
    is_method=False,
    is_parameter=False,
):
    """Retrieve the list of tags assigned to call, method or parameters"""
    suffix = ""
    if is_call:
        suffix = ".call"
    elif is_method:
        suffix = ".method"
    elif is_parameter:
        suffix = ".parameter"
    if name:
        return await client.q(connection, f"""atom.tag.name("{name}"){suffix}""")
    elif value:
        return await client.q(connection, f"""atom.tag.value("{value}"){suffix}""")
    return await client.q(connection, "atom.tag{suffix}")


async def create_tags(connection, query=None, call=None, method=None, tags=None):
    """
    Function to create custom tags on nodes. Nodes could be selected based on a query, or call or method name.

    Tags could be a list of string or dictionary of key, value pairs
    """
    if tags is None:
        tags = []
    if not query and call:
        query = f"""atom.call.name("{call}")"""
    elif not query and method:
        query = f"""atom.method.name("{method}")"""
    if query and tags:
        for tag in tags:
            if isinstance(tag, dict):
                for k, v in tag.items():
                    await client.q(
                        connection,
                        f"""
                        {query}.newTagNodePair("{k}", "{v}").store()
                        run.commit
                        save
                        """,
                    )
            if isinstance(tag, str):
                await client.q(
                    connection,
                    f"""
                {query}.newTagNode("{tag}").store()
                run.commit
                save
                """,
                )


async def list_types(connection):
    """Function to list types"""
    return await client.q(connection, "atom.typ")


async def list_custom_types(connection):
    """Function to list all custom types"""
    return await client.q(
        connection,
        """atom.typeDecl.filterNot(t => t.isExternal || t.name.matches("(:program|<module>|<init>|<meta>|<body>)"))""",
    )


async def get_calls(connection, pattern):
    """Function to list calls"""
    return await client.q(connection, f"""atom.call.code("(?i){pattern}")""")


async def get_method_callIn(connection, pattern):
    """Function to list callIn locations"""
    return await client.q(
        connection, f"""atom.method("(?i){pattern}").callIn.location"""
    )


async def get_identifiers_in_file(connection, filename):
    """Function to list identifiers in a file"""
    return await client.q(
        connection,
        f"""atom.call.assignment.argument.order(1).map(t => (t, t.location.filename)).filter(_._2.equals("{filename}")).filter(_._1.isIdentifier).map(_._1.code).filterNot(_.contains("_tmp_")).dedup""",
    )


async def get_methods_multiple_returns(connection):
    """Function to retrieve methods with multiple return statements"""
    return await get_functions_multiple_returns(connection)


async def get_functions_multiple_returns(connection):
    """Function to retrieve methods with multiple return statements"""
    return await client.q(
        connection,
        """({atom.method.internal.filter(_.ast.isReturn.l.size > 1).nameNot("<global>")}).location""",
    )


async def get_complex_methods(connection, n=4):
    """Function to retrieve complex methods/functions"""
    return await get_complex_functions(connection, n)


async def get_complex_functions(connection, n=4):
    """Function to retrieve complex methods/functions"""
    return await client.q(
        connection,
        """({atom.method.internal.filter(_.controlStructure.size > %(n)d).nameNot("<global>")}).location"""
        % dict(n=n),
    )


async def get_long_methods(connection, n=1000):
    """Function to retrieve long methods/functions"""
    return await get_long_functions(connection, n)


async def get_long_functions(connection, n=1000):
    """Function to retrieve long methods/functions"""
    return await client.q(
        connection,
        """({atom.method.internal.filter(_.numberOfLines > %(n)d).nameNot("<global>")}).location"""
        % dict(n=n),
    )


async def get_too_many_loops_methods(connection, n=4):
    """Function to retrieve methods/functions with many loops"""
    return await get_too_many_loops_functions(connection, n)


async def get_too_many_loops_functions(connection, n=4):
    """Function to retrieve methods/functions with many loops"""
    return await client.q(
        connection,
        """({atom.method.internal.filter(_.ast.isControlStructure.controlStructureType("(FOR|DO|WHILE)").size > %(n)d).nameNot("<global>")}).location"""
        % dict(n=n),
    )


async def get_too_many_params_methods(connection, n=4):
    """Function to retrieve methods/functions with many parameters"""
    return await get_too_many_params_functions(connection, n)


async def get_too_many_params_functions(connection, n=4):
    """Function to retrieve methods/functions with many parameters"""
    return await client.q(
        connection,
        """({atom.method.internal.filter(_.parameter.size > %(n)d).nameNot("<global>")}).location"""
        % dict(n=n),
    )


async def get_too_nested_methods(connection, n=4):
    """Function to retrieve methods/functions that are nested"""
    return await get_too_nested_functions(connection, n)


async def get_too_nested_functions(connection, n=4):
    """Function to retrieve methods/functions that are nested"""
    return await client.q(
        connection,
        """({atom.method.internal.filter(_.depth(_.isControlStructure) > %(n)d).nameNot("<global>")}).location"""
        % dict(n=n),
    )


async def get_call_tree(connection, method_name, n=3):
    """Function to retrieve the call tree of a method"""
    await client.q(
        connection,
        """
import scala.collection.mutable.ListBuffer
def printDashes(count: Int) = {
    var tabStr = "+--- "
    var i = 0
    while (i < count) {
        tabStr = "|    " + tabStr
        i += 1
    }
    tabStr
}
def printCallTree(callerFullName : String, tree: ListBuffer[String], depth: Int): Unit = {
    var dashCount = 0
    var lastCallerMethod = callerFullName
    var lastDashCount = 0
    tree += callerFullName
    def findCallee(methodName: String, tree: ListBuffer[String]): Unit = {
        var calleeList = atom.method.fullNameExact(methodName).callee.whereNot(_.name(".*<operator>.*")).l
        var callerNameList = atom.method.fullNameExact(methodName).caller.fullName.l
        if (callerNameList.contains(lastCallerMethod) || (callerNameList.size == 0)) {
            dashCount = lastDashCount
        } else {
            lastDashCount = dashCount
            lastCallerMethod = methodName
            dashCount += 1
        }
        if (dashCount < depth) {
            calleeList foreach { c =>
                tree += printDashes(dashCount) + c.fullName
                findCallee(c.fullName, tree)
            }
        }
    }
    findCallee(lastCallerMethod, tree)
}
""",
    )
    return await client.q(
        connection,
        """
        var tree = new ListBuffer[String]()
        printCallTree("%(method_name)s", tree, %(n)d)
        tree.toList.mkString("\\n")
        """
        % dict(method_name=method_name, n=n),
    )


async def export(
    connection,
    method=None,
    query=None,
    export_repr="pdg",
    colorize=True,
    as_graph=False,
):
    """Function to export graph representations of a method or node"""
    filter_str = "method"
    if method:
        filter_str = f"method{expand_search_str(method)}"
    elif query:
        filter_str = query.replace("atom.", "")
    if as_graph:
        gml_file = await client.graphml_export(connection, filter_str=filter_str)
        return graph.convert_graphml(gml_file, as_graph=True)
    res = await client.q(
        connection, f"""atom.{filter_str}.dot{export_repr.capitalize()}"""
    )
    return (
        colorize_dot_data(res)
        if colorize
        else (res[0] if res and len(res) == 1 else res)
    )


async def summary(connection):
    return await client.q(connection, "summary(true)")


async def files(connection, title="Files"):
    return await client.q(connection, f'files(title="{title}", true)')


def bool_to_str(b):
    return "true" if b else "false"


async def methods(connection, title="Methods", include_calls=False, tree=False):
    return await client.q(
        connection,
        f'methods(title="{title}", includeCalls={bool_to_str(include_calls)}, tree={bool_to_str(tree)}, as_text=true)',
    )


async def annotations(connection, title="Annotations"):
    return await client.q(connection, f'annotations(title="{title}", true)')


async def imports(connection, title="Imports"):
    return await client.q(connection, f'imports(title="{title}", true)')


async def declarations(connection, title="Declarations"):
    return await client.q(connection, f'declarations(title="{title}", as_text=true)')


async def sensitive(
    connection, title="Sensitive", pattern="(secret|password|token|key|admin|root)"
):
    return await client.q(
        connection, f'sensitive(title="{title}", pattern="{pattern}", as_text=true)'
    )


async def show_similar(
    connection, method_fullname, compare_pattern="", upper_bound=500, timeout=5
):
    return await client.q(
        connection,
        f'showSimilar(methodFullName="{method_fullname}", comparePattern="{compare_pattern}", upper_bound={upper_bound}, timeout={timeout}, as_text=true)',
    )
