import os

import httpx

# GitHub advisory feed url
ghsa_api_url = os.getenv("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql")
api_token = os.getenv("GITHUB_TOKEN")
headers = {"Authorization": f"token {api_token}"}

ecosystem_type_dict = {
    "go": "golang",
    "rust": "cargo",
    "pip": "pypi",
    "rubygems": "gem",
}


def get_query(cve_or_ghsa=None, only_malware=False, extra_clause=None):
    """Method to construct the graphql query"""
    extra_args = ""
    if not cve_or_ghsa:
        extra_args = "first: 100"
    else:
        id_type = "GHSA" if cve_or_ghsa.startswith("GHSA") else "CVE"
        extra_args = (
            'first: 100, identifier: {type: %(id_type)s, value: "%(cve_or_ghsa)s"}'
            % dict(id_type=id_type, cve_or_ghsa=cve_or_ghsa)
        )
    if only_malware:
        extra_args = f"{extra_args}, classifications:MALWARE"
    if extra_clause:
        extra_args = f"{extra_args}, {extra_clause}"
    gqljson = {
        "query": """
            {
                securityAdvisories(
                    %(extra_args)s
                ) {
                    nodes {
                    id
                    ghsaId
                    summary
                    description
                    identifiers {
                        type
                        value
                    }
                    origin
                    publishedAt
                    updatedAt
                    references {
                        url
                    }
                    severity
                    withdrawnAt
                    vulnerabilities(first: 10) {
                        nodes {
                        firstPatchedVersion {
                            identifier
                        }
                        package {
                            ecosystem
                            name
                        }
                        severity
                        updatedAt
                        vulnerableVersionRange
                        }
                    }
                    }
                }
            }
        """
        % dict(extra_args=extra_args)
    }
    return gqljson


def parse_response(json_data):
    """Parse json response and convert to list of purls"""
    purl_list = []
    for node in (
        json_data.get("data", {}).get("securityAdvisories", {}).get("nodes", {})
    ):
        ghsa_id = node.get("ghsaId")
        vulnerable_nodes = node.get("vulnerabilities", {}).get("nodes", [])
        for vn in vulnerable_nodes:
            pkg = vn.get("package", {})
            version = ""
            if vn.get("firstPatchedVersion"):
                version = vn.get("firstPatchedVersion", {}).get("identifier", "")
            elif vn.get("vulnerableVersionRange"):
                version = vn.get("vulnerableVersionRange").split(" ")[-1]
            if pkg:
                ptype = pkg.get("ecosystem", "").lower()
                pname = pkg.get("name", "").lower().replace(":", "/")
                # This is the fixed version
                if ptype and pname and version:
                    purl = (
                        f"pkg:{ecosystem_type_dict.get(ptype, ptype)}/{pname}@{version}"
                    )
                    purl_list.append(
                        {
                            "ghsaId": ghsa_id,
                            "purl": purl,
                        }
                    )
    return purl_list


def get_download_urls(cve_or_ghsa=None, only_malware=False):
    """Method to get download urls for the packages belonging to the CVE"""
    if not api_token:
        raise ValueError("GITHUB_TOKEN is required with read:packages scope")
    client = httpx.Client(http2=True, follow_redirects=True, timeout=180)
    r = client.post(
        url=ghsa_api_url,
        json=get_query(cve_or_ghsa=cve_or_ghsa, only_malware=only_malware),
        headers=headers,
    )
    json_data = r.json()
    return parse_response(json_data)
