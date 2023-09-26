"""
Module to detect common functions used in javascript/typescript applications
"""
from chenpy import client
from chenpy.detectors.common import get_calls

REQUEST_PATTERN = """(?s)(?i).*(req|ctx)\\.(originalUrl|path|protocol|route|secure|signedCookies|stale|subdomains|xhr|app|pipe|file|files|baseUrl|fresh|hostname|ip|url|ips|method|body|param|params|query|cookies|request).*"""

RESPONSE_PATTERN = """(?s)(?i).*res\\.(append|attachment|cookie|clearCookie|download|end|format|get|json|jsonp|links|location|redirect|render|send|sendFile|sendStatus|set|status|type|vary).*"""

HEADER_SINK_PATTERN = """(?s)(?i).*res\\.(set|writeHead|setHeader).*"""

DB_SINK_PATTERN = """(?s)(?i).*(db|dao|mongo|mongoclient).*"""


async def list_http_routes(
    connection,
    app_vars="(app|router)",
    http_methods="(head|get|post|put|patch|delete|options)",
    include_middlewares=True,
):
    """Retrieve the list of http routes"""
    if include_middlewares:
        return await client.q(
            connection,
            f"""atom.call.code(".*{app_vars}.{http_methods}.*").argument.orderGte(3).location""",
        )
    else:
        return await client.q(
            connection,
            f"""atom.call.code(".*{app_vars}.{http_methods}.*").argument.order(3).location""",
        )


async def get_express_appvar(connection):
    """Retrieve the variable that requires the express framework"""
    return await get_framework_appvar(connection, "express")


async def get_koa_appvar(connection):
    """Retrieve the variable that requires the koa framework"""
    return await get_framework_appvar(connection, "koa")


async def get_framework_appvar(connection, framework):
    """Retrieve the variable that requires the framework"""
    return await client.q(
        connection,
        f"""atom.call.assignment.code(".*{framework}\\\\(.*").argument.order(1)""",
    )


async def get_framework_config(connection, app_var="app"):
    """Retrieve the variable that stores the framework configuration"""
    return await client.q(connection, f"""atom.call.code("{app_var}.*").receivedCall""")


async def list_requires(connection, require_var="require"):
    """Retrieve the list of require statements"""
    return await client.q(
        connection,
        f'atom.call.assignment.code(".*{require_var}\\\\(.*").argument.order(1)',
    )


async def list_requires_location(connection, require_var="require"):
    """Retrieve the list of require statements and their locations"""
    return await client.q(
        connection,
        f'atom.call.assignment.code(".*{require_var}\\\\(.*").argument.order(1).map(t => (t, t.location)).filter(_._1.isIdentifier).dedup',
    )


async def list_nosql_collections(connection, db_list="(db|mongo)"):
    """Retrieve the list of NoSql database collections referred in the code"""
    return await client.q(
        connection,
        f'atom.call.code("{db_list}\\.collection.*").argument.order(3).location',
    )


async def list_imports(connection):
    """Retrieve the list of import statements"""
    return await client.q(connection, 'atom.dependency.version("import")')


async def list_aws_modules(connection):
    """Retrieve the list of AWS SDK modules"""
    return await list_sdk_modules(connection, "aws")


async def list_koa_modules(connection):
    """Retrieve the list of koa framework modules"""
    return await list_sdk_modules(connection, "koa")


async def list_sdk_modules(connection, sdk):
    """Retrieve the list of modules for any sdk"""
    return await client.q(
        connection,
        f'atom.call.assignment.code(".*require\\\\(.*").argument.isIdentifier.filter(_.typeFullName.contains("{sdk}")).map(t => (t, t.location)).filter(_._1.isIdentifier).dedup',
    )


async def used_aws_modules(connection):
    """Retrieve the list of used AWS SDK modules"""
    return await used_sdk_modules(connection, "aws")


async def used_koa_modules(connection):
    """Retrieve the list of used koa modules"""
    return await used_sdk_modules(connection, "koa")


async def used_sdk_modules(connection, sdk):
    """Retrieve the list of used SDK modules"""
    return await client.q(
        connection,
        f'atom.call.name("<operator>.new").receiver.isIdentifier.filter(_.typeFullName.contains("{sdk}")).map(t => (t, t.location)).filter(_._1.isIdentifier).dedup',
    )


async def get_http_sources(connection, source=REQUEST_PATTERN):
    """Retrieve the list of common http sources based on convention"""
    return await get_calls(connection, source)


async def get_http_sinks(connection, sink=RESPONSE_PATTERN):
    """Retrieve the list of common http sinks based on convention"""
    return await get_calls(connection, sink)


async def get_http_header_sinks(connection, sink=HEADER_SINK_PATTERN):
    """Retrieve the list of common http headers sinks based on convention"""
    return await get_calls(connection, sink)


async def get_db_sinks(connection, sink=DB_SINK_PATTERN):
    """Retrieve the list of common db sinks based on convention"""
    return await get_calls(connection, sink)
