"""
Functions to perform workspace related operations
"""
import json
import os

from chenpy import client


def extract_dir(res):
    """Extract the directory name from the AtomQL response"""
    if res.get("response"):
        dir_name = res.get("response").split('String = "')[-1].split('"')[0]
        return dir_name
    return None


async def ls(connection):
    """Retrieves the list of Atoms in the workspace"""
    res = await client.q(connection, "workspace")
    if "[io.appthreat.chencli.console.ChenProject] = empty" in res.get("response", ""):
        return None
    return res.get("response")


async def slice_cpg(
    connection,
    src,
    out_dir=None,
    languages="autodetect",
    project_name=None,
    slice_mode="Usages",
):
    """Function to slice the Atom based on a slice mode"""
    app_manifests = await create_cpg(
        connection,
        src,
        out_dir=out_dir,
        languages=languages,
        project_name=project_name,
        slice=True,
        slice_mode=slice_mode,
    )
    if not app_manifests:
        return None
    if isinstance(app_manifests, (list, tuple)):
        app_manifests = app_manifests[0]
    if app_manifests.get("slice_out") and os.path.exists(
        app_manifests.get("slice_out")
    ):
        try:
            with open(app_manifests.get("slice_out"), encoding="utf-8") as fp:
                return json.load(fp)
        except json.JSONDecodeError:
            return None
    return None


async def create_atom(
    connection,
    src,
    out_dir=None,
    languages="autodetect",
    project_name=None,
):
    """Function to create atom using atomgen server"""
    return await create_cpg(
        connection,
        src,
        out_dir=out_dir,
        languages=languages,
        project_name=project_name,
        slice=False,
        slice_mode="Usages",
        auto_build=True,
        skip_sbom=False,
        use_atom=True,
    )


async def create_cpg(
    connection,
    src,
    out_dir=None,
    languages="autodetect",
    project_name=None,
    slice=None,
    slice_mode="Usages",
    auto_build=True,
    skip_sbom=True,
    use_atom=False,
):
    """Function to create Atom using atomgen server"""
    app_manifests = []
    res = await client.create_cpg(
        connection,
        src,
        out_dir=out_dir,
        lang=languages,
        slice=slice,
        slice_mode=slice_mode,
    )
    if res:
        app_manifests = res.get("app_manifests", [])
        if app_manifests:
            first_app = app_manifests[0]
            if not project_name and first_app.get("app"):
                project_name = first_app.get("app")
            cpg_path = first_app.get("cpg")
            res = await import_atom(connection, cpg_path, project_name)
            if not res:
                return None
    return (
        app_manifests[0] if app_manifests and len(app_manifests) == 1 else app_manifests
    )


async def import_atom(connection, cpg_path, project_name=None):
    """Function to import Atom"""
    if cpg_path:
        res = await dir_exists(connection, cpg_path)
        if not res:
            raise ValueError(
                f"Atom {cpg_path} doesn't exist for import into chen. Check if the directory containing this Atom is mounted and accessible from the server."
            )
    if project_name:
        res = await client.q(
            connection, f"""importCpg("{cpg_path}", "{project_name}")"""
        )
    else:
        res = await client.q(connection, f"""importCpg("{cpg_path}")""")
    if isinstance(res, str):
        return False
    return True


async def import_code(connection, directory, project_name=None, language=""):
    """Function to import code to chen"""
    if project_name:
        res = await client.q(
            connection,
            f"""importCode("{directory}", projectName="{project_name}", language="{language.upper()}")""",
        )
    else:
        res = await client.q(
            connection, f"""importCode("{directory}", language="{language.upper()}")"""
        )
    if isinstance(res, str):
        return False
    if "io.shiftleft.codepropertygraph.Cpg" in res.get("response", ""):
        return True
    return False


async def from_string(connection, code_snippet, language="jssrc"):
    """Function to import string"""
    res = await client.q(
        connection, f'importCode.{language}.fromString("""{code_snippet}""")'
    )
    if isinstance(res, str):
        return False
    if res and "Code successfully imported" in res.get("response", ""):
        return True
    return False


async def reset(connection):
    """Function to reset workspace"""
    await client.q(connection, "workspace.reset")
    return True


async def get_path(connection):
    """Function to retrieve the path to a workspace"""
    res = await client.q(connection, "workspace.getPath")
    return extract_dir(res)


async def get_active_project(connection):
    """Function to retrieve active project"""
    return await client.q(connection, "workspace.getActiveProject")


async def set_active_project(connection, project_name):
    """Function to set active project"""
    res = await client.q(
        connection, f"""workspace.setActiveProject("{project_name}")"""
    )
    if isinstance(res, str):
        return False
    if res and "projectFile = ProjectFile(inputPath =" in res.get("response", ""):
        return True
    return False


async def delete_project(connection, project_name):
    """Function to delete a project"""
    return await client.q(connection, f"""workspace.deleteProject("{project_name}")""")


async def cpg_exists(connection, project_name):
    """Function to check if a Atom exists in the workspace"""
    if project_name:
        res = await client.q(connection, f"""workspace.cpgExists("{project_name}")""")
        if res and "Boolean = true" in res.get("response", ""):
            return True
    return False


async def get_overlay_dir(connection, project_name):
    """Function to retrieve the overlays of a project"""
    res = await client.q(
        connection, f"""workspace.overlayDirByProjectName("{project_name}")"""
    )
    return extract_dir(res)


async def dir_exists(connection, dir_name):
    """Function to check if a directory exists and is accessible from the chen server"""
    res = await client.q(connection, f"""os.exists(os.Path("{dir_name}"))""")
    if res and "Boolean = true" in res.get("response", ""):
        return True
    return False
