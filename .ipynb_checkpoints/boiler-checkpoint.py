"""
boiler.py — Rust in the Boiler: Spotting the Liars in Your Domain
==================================================================
All the machinery behind the demo notebook, so that every phase of the
notebook is one instruction and one short cell.

Author : Luis F. Monge (@Lucky-Luk3) · grexid.eu
License: CC BY 4.0

Phases
  1. collect()  / load_saved()          -> df_users, df_groups          (Layer 1 data)
  2. risk_ranking(df)                   -> top-N table by risk score    (Layer 1)
  3. domain_map(df) / rights_origin()   -> interactive graph view       (Layer 2)
  4. anomaly_consensus(df)              -> ML object + top-N report     (Layer 3)
     anomaly_map(ml)                    -> 3D PCA plot
  5. semantic_search(ml, q)             -> plain-language search        (Layer 4)
     incoherence(ml)                    -> the liars
     llm_explain(ml, n)                 -> local LLM report
"""
import os, glob, json, re, hmac, hashlib, base64, datetime, multiprocessing, urllib.parse
from time import time
from typing import Optional

import numpy as np
import pandas as pd
import requests
from tqdm import tqdm
from IPython import get_ipython
from IPython.display import display, Markdown, clear_output

tqdm.pandas()
pd.set_option("display.float_format", lambda x: f"{x:.3f}")
pd.set_option("display.max_colwidth", 80)

# ---------------------------------------------------------------------------
# BloodHound CE client and processing functions (verbatim from the original notebook)
# ---------------------------------------------------------------------------
class Credentials(object):
    def __init__(self, token_id: str, token_key: str) -> None:
        self.token_id = token_id
        self.token_key = token_key


class APIVersion(object):
    def __init__(self, api_version: str, server_version: str) -> None:
        self.api_version = api_version
        self.server_version = server_version


class Domain(object):
    def __init__(self, name: str, id: str, collected: bool, domain_type: str) -> None: #, impact_value: int
        self.name = name
        self.id = id
        self.type = domain_type
        self.collected = collected
        #self.impact_value = impact_value


class AttackPath(object):
    def __init__(self, id: str, title: str, domain: Domain) -> None:
        self.id = id
        self.title = title
        self.domain_id = domain.id
        self.domain_name = domain.name.strip()

    def __lt__(self, other):
        return self.exposure < other.exposure

class Client(object):
    def __init__(self, scheme: str, host: str, port: int, credentials: Credentials) -> None:
        self._scheme = scheme
        self._host = host
        self._port = port
        self._credentials = credentials

    def _format_url(self, uri: str) -> str:
        uri = uri.lstrip("/")
        return f"{self._scheme}://{self._host}:{self._port}/{uri}"

    def _request(self, method: str, uri: str, body: Optional[dict] = None) -> requests.Response:
        # 1. Inicializar con b"" en lugar de None
        digester = hmac.new(self._credentials.token_key.encode(), b"", hashlib.sha256)
        
        # OperationKey
        digester.update(f"{method}{uri}".encode())
        
        # Re-inicializar para encadenamiento
        digester = hmac.new(digester.digest(), b"", hashlib.sha256)
        
        # DateKey (Truncado a la hora: YYYY-MM-DDTHH)
        datetime_formatted = datetime.datetime.now(datetime.timezone.utc).isoformat()
        digester.update(datetime_formatted[:13].encode())
        
        # Re-inicializar para encadenamiento
        digester = hmac.new(digester.digest(), b"", hashlib.sha256)
        
        # Body signing
        if body is not None:
            # Importante: usar separadores compactos para que el JSON coincida con lo que el servidor espera firmar
            json_body = json.dumps(body, separators=(',', ':'))
            digester.update(json_body.encode('utf-8'))

        # 2. .decode() en la firma para pasar de bytes a string
        signature = base64.b64encode(digester.digest()).decode()

        return requests.request(
            method=method,
            url=self._format_url(uri),
            headers={
                "User-Agent": "bhe-python-sdk 0002",
                "Authorization": f"bhesignature {self._credentials.token_id}",
                "RequestDate": datetime_formatted,
                "Signature": signature,
                "Content-Type": "application/json"
            },
            json=body,
        )

    def get_version(self) -> APIVersion:
        # BloodHound CE usa /api/v2/version o /api/v2/self para probar
        # Si usas /api/version asegúrate que el contenedor lo soporte
        response = self._request("GET", "/api/v2/self")
        response.raise_for_status()
        payload = response.json()
        
        # Ajusta estas claves según la respuesta real de tu contenedor
        return APIVersion(
            api_version="v2", 
            server_version="Community Edition"
        )
    def get_domains(self):
        response = self._request('GET', '/api/v2/available-domains')
        payload = response.json()['data']

        domains = list()
        #print(payload)
        for domain in payload:
            domains.append(Domain(domain["name"], domain["id"], domain["collected"], domain["type"])) #, domain["impactValue"]

        return domains

    def get_domains_ids(self):
        response = self._request('GET', '/api/v2/available-domains')
        payload = response.json()['data']

        domains = []
        #print(payload)
        for domain in payload:
            domains.append(domain["id"])

        return domains

    def get_users(self, domain_id, limit=200000):
        response = self._request('GET', "/api/v2/domains/{}/users?limit={}".format(domain_id, limit))
        response_data = response.json()
        if "data" in response_data:
            payload = response_data['data']
        else:
            print(f"Error requesting users in {domain_id} domain.")
            payload = ""

        #users = list()
        #print(payload)
        #for domain in payload:
            #domains.append(Domain(domain["name"], domain["id"], domain["collected"], domain["type"])) #, domain["impactValue"]

        return payload

    def get_groups(self, domain_id, limit=200000):
        response = self._request('GET', '/api/v2/domains/{}/groups?limit={}'.format(domain_id, limit))
        response_data = response.json()
        if "data" in response_data:
            payload = response_data['data']
        else:
            print(f"Error requesting groups in {domain_id} domain.")
            payload = ""

        #users = list()
        #print(payload)
        #for domain in payload:
            #domains.append(Domain(domain["name"], domain["id"], domain["collected"], domain["type"])) #, domain["impactValue"]

        return payload

    def get_attack_path_types(self):
        response = self._request('GET', '/api/v2/attack-path-types')
        print(response)
        payload = response.json()['data']

        attack_path_types = list()
        for apt in payload:
            attack_path_types.append(apt)

        return attack_path_types

    def get_paths(self, domain: Domain) -> list:
        response = self._request('GET', '/api/v2/domains/' + domain.id + '/available-types')
        path_ids = response.json()['data']

        paths = list()
        for path_id in path_ids:
            # Get nice title from API and strip newline
            path_title = self._request('GET', '/ui/findings/' + path_id + '/title.md')

            # Create attackpath object
            path = AttackPath(path_id, path_title.text.strip(), domain)
            paths.append(path)

        return paths

    def get_path_principals(self, path: AttackPath) -> list:
        # Get path details from API
        response = self._request('GET', '/api/v2/domains/' + path.domain_id + '/details?finding=' + path.id + '&skip=0&limit=0&Accepted=eq:False')
        payload = response.json()

        # Build dictionary of impacted pricipals
        if 'count' in payload:
            path.impacted_principals = list()
            for path_data in payload['data']:
                # Check for both From and To to determine whether relational or configuration path
                if (path.id.startswith('LargeDefault')):
                    from_principal = path_data['FromPrincipalProps']['name']
                    to_principal = path_data['ToPrincipalProps']['name']
                    principals = {
                        'Group': from_principal,
                        'Principal': to_principal
                    }
                elif ('FromPrincipalProps' in path_data) and ('ToPrincipalProps' in path_data):
                    from_principal = path_data['FromPrincipalProps']['name']
                    to_principal = path_data['ToPrincipalProps']['name']
                    principals = {
                        'Non Tier Zero Principal': from_principal,
                        'Tier Zero Principal': to_principal
                    }
                else:
                    principals = {
                        'User': path_data['Props']['name']
                    }
                path.impacted_principals.append(principals)
                path.principal_count = payload['count']
        else:
            path.principal_count = 0

        return path

    def get_path_timeline(self, path: AttackPath, from_timestamp: str, to_timestamp: str):
        # Sparkline data
        response = self._request('GET', '/api/v2/domains/' + path.domain_id + '/sparkline?finding=' + path.id + '&from=' + from_timestamp + '&to=' + to_timestamp)
        exposure_data = response.json()['data']

        events = list()
        for event in exposure_data:
            e = {}
            e['finding_id'] = path.id
            e['domain_id'] = path.domain_id
            e['path_title'] = path.title
            e['exposure'] = event['CompositeRisk']
            e['finding_count'] = event['FindingCount']
            e['principal_count'] = event['ImpactedAssetCount']
            e['id'] = event['id']
            e['created_at'] = event['created_at']
            e['updated_at'] = event['updated_at']
            e['deleted_at'] = event['deleted_at']

            # Determine severity from exposure
            e['severity'] = self.get_severity(e['exposure'])
            events.append(e)

        return events

    def get_posture(self, from_timestamp: str, to_timestamp: str) -> list:
        response = self._request('GET', '/api/v2/posture-stats?from=' + from_timestamp + '&to=' + to_timestamp)
        payload = response.json()
        return payload["data"]

    def get_severity(self, exposure: int) -> str:
        severity = 'Low'
        if exposure > 40: severity = 'Moderate'
        if exposure > 80: severity = 'High'
        if exposure > 95: severity = 'Critical'
        return severity

    def exec_cypher_query(self, query: str) -> dict:
        body = {"query": query}
        response = self._request('POST', '/api/v2/graphs/cypher', body=body)
        if "data" in response.json():
            payload = response.json()['data']
        else:
            print("No data")
            payload = response

        #nodes = []
        #for d in payload["nodes"]:
            #nodes.append(payload["nodes"][d])

        #edges = []
        #for d in payload["edges"]:
            #edges.append(d)

        #df_nodes = pd.DataFrame.from_records(nodes)
        #df_edges = pd.DataFrame.from_records(edges)

        #return df_nodes, df_edges

        #nodes = payload["nodes"]

        #domains = list()
        #print(payload)
        #for domain in payload:
            #domains.append(Domain(domain["name"], domain["id"], domain["collected"], domain["type"])) #, domain["impactValue"]

        return payload

    def search(self, query: str) -> pd.DataFrame:
        body = urllib.parse.quote(query)
        response = self._request('GET', f'/api/v2/search?q={body}')
        payload = response.json()['data']
        results = []
        for d in payload:
            results.append(d)
        df_result = pd.DataFrame.from_records(results)

        return df_result


    def get_data_quality_stats(self, domain_id: str) -> dict:
        response = self._request('GET', f'/api/v2/ad-domains/{domain_id}/data-quality-stats?limit=100')
        payload = response.json()['data']

        return payload


    def get_shortest_path(self, start_node: str, end_node: str, relationship_kinds: Optional[list] = None) -> tuple:
        # 1. Usamos una lista más corta y segura para probar (todas están en tu lista de 'acceptable')
        if relationship_kinds is None:
            rels = [
                "Owns", "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl", 
                "MemberOf", "ForceChangePassword", "AllExtendedRights", "AddMember", 
                "HasSession", "Contains", "GPLink", "AllowedToDelegate", "TrustedBy", 
                "AllowedToAct", "AdminTo", "CanPSRemote", "ExecuteDCOM", "HasSIDHistory", 
                "AddSelf", "DCSync", "ReadLAPSPassword", "ReadGMSAPassword", 
                "DumpSMSAPassword", "SQLAdmin", "AddAllowedToAct", "WriteSPN", 
                "AddKeyCredentialLink", "SyncLAPSPassword", "WriteAccountRestrictions"
            ]
        else:
            rels = relationship_kinds
    
        # 2. PROBAMOS EL FORMATO SIMPLE (Solo los nombres separados por coma, sin "in:")
        # La mayoría de las versiones de la API v2 prefieren esto en el backend
        rels_str = ",".join(rels)
    
        # 3. Construcción manual de la URL para control total
        # No usamos urlencode en el 'rels_str' para evitar que las comas se conviertan en %2C
        # a menos que sea estrictamente necesario.
        path = f"/api/v2/graphs/shortest-path?start_node={start_node}&end_node={end_node}&relationship_kinds={rels_str}"
        
        response = self._request('GET', path)
        res_json = response.json()
    
        # Si falla sin el "in:", intentamos CON el "in:" automáticamente
        if response.status_code == 400 and "acceptable values should match the format" in str(res_json):
            path_with_in = f"/api/v2/graphs/shortest-path?start_node={start_node}&end_node={end_node}&relationship_kinds=in:{rels_str}"
            response = self._request('GET', path_with_in)
            res_json = response.json()
    
        if response.status_code != 200:
            print(f"Error persistente en la API: {res_json}")
            return pd.DataFrame(), pd.DataFrame()
    
        # ... (resto del código de procesamiento de nodos y edges igual que antes)
        payload = res_json.get('data', {})
        nodes = []
        for key, value in payload.get("nodes", {}).items():
            temp = value.copy()
            temp["id"] = key
            nodes.append(temp)
        edges = payload.get("edges", [])
        
        return pd.DataFrame.from_records(nodes, index="id") if nodes else pd.DataFrame(), \
               pd.DataFrame.from_records(edges) if edges else pd.DataFrame()

    def get_user_ncontrollers(self, user_id):
        response = self._request('GET', '/api/v2/users/{}/controllers?limit=1'.format(user_id))
        n = response.json()['count']

        return n

    def get_user_controllers(self, user_id):
        response = self._request('GET', '/api/v2/users/{}/controllers?limit=10000'.format(user_id))
        controllers = response.json()['data']

        df_controllers = pd.DataFrame.from_records(controllers)

        return df_controllers

    def get_user_ncontrollables(self, user_id):
        response = self._request('GET', '/api/v2/users/{}/controllables?limit=1'.format(user_id))
        n = response.json()['count']

        return n

    def get_user_controllables(self, user_id):
        response = self._request('GET', '/api/v2/users/{}/controllables?limit=10000'.format(user_id))
        controllables = response.json()['data']

        df_controllables = pd.DataFrame.from_records(controllables)

        return df_controllables

    def get_group_ncontrollables(self, group_id):
        response = self._request('GET', '/api/v2/groups/{}/controllables'.format(group_id))
        n = response.json()['count']

        return n

    def get_group_controllables(self, group_id):
        response = self._request('GET', '/api/v2/groups/{}/controllables'.format(group_id))
        controllables = response.json()['data']

        return pd.DataFrame.from_records(controllables)

    def get_group_ncontrollers(self, group_id):
        response = self._request('GET', '/api/v2/groups/{}/controllers?limit=1'.format(group_id))
        n = response.json()['count']

        return n

    def get_group_controllers(self, group_id):
        response = self._request('GET', '/api/v2/groups/{}/controllers?limit=10000'.format(group_id))
        controllers = response.json()['data']

        df_controllers = pd.DataFrame.from_records(controllers)

        return df_controllers

    def get_group_nmembers(self, group_id):
        response = self._request('GET', '/api/v2/groups/{}/members'.format(group_id))
        n = response.json()['count']

        return n

    def get_user_membership(self, user_id):
        response = self._request('GET', '/api/v2/users/{}/memberships?limit=10000'.format(user_id))
        memberships = response.json()['data']

        #df_controllables = pd.DataFrame.from_records(controllables)
        #users = list()
        #print(payload)
        #for domain in payload:
            #domains.append(Domain(domain["name"], domain["id"], domain["collected"], domain["type"])) #, domain["impactValue"]

        return memberships

    def get_user_attrib(self, user_id, attrib):
        response = self._request('GET', '/api/v2/users/{}'.format(user_id))
        attribute = response.json()['data']['props'][attrib]

        return attribute

    def get_user_enabled(self, user_id):
        response = self._request('GET', '/api/v2/users/{}'.format(user_id))
        props = response.json()['data']['props']
        if 'enabled' in props:
            attribute = response.json()['data']['props']['enabled']
        else:
            attribute = 'error'

        return attribute

from certeu_utils import get_user_ncontrollables,get_user_ncontrollers,get_group_ncontrollables,get_group_ncontrollers,get_user_info,get_user_infov2,get_group_infov2,get_group_members
import multiprocessing

def bh_connect(BHE_TOKEN_ID, BHE_TOKEN_KEY, BHE_SCHEME, BHE_DOMAIN, BHE_PORT):

    credentials = Credentials(
        token_id=BHE_TOKEN_ID,
        token_key=BHE_TOKEN_KEY,
    )

    client = Client(scheme=BHE_SCHEME, host=BHE_DOMAIN, port=BHE_PORT, credentials=credentials)
    try:
        client.get_version()
        print("  BloodHound connection OK")
    except Exception as e:
        raise ConnectionError(f"Cannot reach BloodHound CE at {BHE_SCHEME}://{BHE_DOMAIN}:{BHE_PORT} — check host, port and token ({e})")

    return client

def process_users(client, domains, limit=200000):
    #list of domains
    users = []
    for domain in domains:
        users.extend( client.get_users(domain, limit))
    #print(users)
    df_users = pd.DataFrame.from_records(users)

    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        results = pool.map(get_user_ncontrollables, df_users["objectID"])
    df_users["ncontrollables"] = results

    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        results = pool.map(get_user_ncontrollers, df_users["objectID"])
    df_users["ncontrollers"] = results

    df_users["control_risk"] = df_users["ncontrollables"] * (df_users["ncontrollers"]) #Test other combinations
    #df_users["ncontrollables"] = df_users[:10]["objectID"].apply(client.get_user_ncontrollables)
    #df_users["ncontrollers"] = df_users[:10]["objectID"].apply(client.get_user_ncontrollers)


    return df_users

def process_usersv2(client, domains, df_users_init, limit=200000):

    df_users_init = df_users_init.rename(columns={'ObjectIdentifier':'objectID'})
    rows = df_users_init[:limit].to_dict('records')

    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        results = pool.map(get_user_infov2, rows)

    df_users = pd.DataFrame.from_records([r for r in results if r is not None])
    #df_users = pd.DataFrame.from_records(results, index='objectid')
    #df_users = pd.DataFrame.from_records(results)

    #df_users["control_risk"] = df_users["controllables"] * (df_users["controllers"])

    return df_users

def process_groups(client, domains, limit=200000):
    #list of domains
    groups = []
    for domain in domains:
        groups.extend( client.get_groups(domain, limit))

    df_groups = pd.DataFrame.from_records(groups)
    #df_groups["ncontrollables"] = df_groups[:10]["objectID"].apply(client.get_group_ncontrollables)
    #df_groups["ncontrollers"] = df_groups[:10]["objectID"].apply(client.get_group_ncontrollers)

    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        results = pool.map(get_group_ncontrollables, df_groups["objectID"])
    df_groups["ncontrollables"] = results

    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        results = pool.map(get_group_ncontrollers, df_groups["objectID"])
    df_groups["ncontrollers"] = results

    df_groups["control_risk"] = df_groups["ncontrollables"] * (df_groups["ncontrollers"]) #Test other combinations

    return df_groups

def process_groupsv2(client, domains, df_groups_init, limit=200000):

    df_groups_init = df_groups_init.rename(columns={'ObjectIdentifier':'objectID'})
    rows = df_groups_init[:limit].to_dict('records')
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        results = pool.map(get_group_infov2, rows)

    #df_groups = pd.DataFrame.from_records(results, index='objectid')
    df_groups = pd.DataFrame.from_records(results)

    return df_groups

def processBHfolder(path):
    data = {}
    json_files = glob.glob(os.path.join(path, "*.json"))
    for file in json_files:
        #print(f"Processing file: {file}.")
        filename = os.path.basename(file).replace(".json", "")
        suf = filename.split("_")[-1]

        with open(file, 'r', encoding='utf-8') as f:
            content = json.load(f)

        if "data" in content:
            if suf in data:
                data[f"{suf}"].extend(content["data"])
            else:
                data[f"{suf}"] = content["data"]
        else:
            print(f"Advertencia: La clave 'data' no se encontró en {file}.")
    return data

def processData(JSONdata):
    result = {}
    result["domains_hashes"] = {}
    result["domains_names"] = {}
    result["ous_hashes"] = {}
    result["ous_names"] = {}
    result["ous_names"] = {}
    result["users_names"]= {}
    result["groups_names"]= {}


    for domain in JSONdata["domains"]:
        for hash in domain["InheritanceHashes"]:
            if hash in result["domains_hashes"]:
                result["domains_hashes"][hash].append(domain['Properties']['distinguishedname'])
            else:
                result["domains_hashes"][hash] = [domain['Properties']['distinguishedname']]
        result["domains_names"][domain['ObjectIdentifier']] = domain['Properties']['name']

    for ou in JSONdata["ous"]:
        for hash in ou["InheritanceHashes"]:
            if hash in result["ous_hashes"]:
                result["ous_hashes"][hash].append(ou['Properties']['distinguishedname'])
            else:
                result["ous_hashes"][hash] = [ou['Properties']['distinguishedname']]
        result["ous_names"][ou['ObjectIdentifier']] = ou['Properties']['name']

    for group in JSONdata["groups"]:
        result["groups_names"][group['ObjectIdentifier']] = group['Properties']['name']

    users_init = []
    for user in JSONdata["users"]:
        result["users_names"][user['ObjectIdentifier']] = user['Properties']['name']
        properties = user.get('Properties', {})

        row = {}
        for key in user:
            if key not in ['Properties']:
                row[key] = user[key]

        for key in properties:
            row[key] = properties[key]

        users_init.append(row)

    df_users_init = pd.DataFrame.from_records(users_init)

    groups_init = []
    for group in JSONdata["groups"]:
        result["groups_names"][user['ObjectIdentifier']] = group['Properties']['name']
        properties = group.get('Properties', {})

        row = {}
        for key in group:
            if key not in ['Properties']:
                row[key] = group[key]

        for key in properties:
            row[key] = properties[key]

        groups_init.append(row)

    df_groups_init = pd.DataFrame.from_records(groups_init)

    return result, df_users_init, df_groups_init

def get_user_aces(data, result, destname, srcname=""):
    results = []
    destination = {}
    found = False
    for user in data["users"]:
        if user['Properties']['name'].startswith(destname):
            destination = user
            found = True
            break
    if not found:
        for group in data["groups"]:
            if group['Properties']['name'].startswith(destname):
                destination = group
                found = True
                break
    if not found:
        for ou in data["ous"]:
            if ou['Properties']['name'].startswith(destname):
                destination = ou
                found = True
                break
    if not found:
        for computer in data["computers"]:
            if computer['Properties']['name'].startswith(destname):
                destination = computer
                found = True
                break
    if not found:
        print("Destination not found in Users, Groups or OUs")
        return False

    #print(f"New user: {user['Properties']['name']} N Aces: {len(user['Aces'])}")
    for ace in destination['Aces']:
        if "User" in ace['PrincipalType']:
            name = result["users_names"][ace['PrincipalSID']]

        elif "Group" in ace['PrincipalType']:
            name = result['groups_names'][ace['PrincipalSID']]

        elif "Base" in ace['PrincipalType']:
            name = "NA"
            originType = "NA"
            origin = ace['InheritanceHash']
            print(ace)
        else:
            print(f"something is not user or group: {ace['PrincipalType']}")
            print(f"something is not user or group: {ace}")

        if not name.startswith(srcname):
            continue

        #print(f"User: {users_names[ace['PrincipalSID']]} Rigts: {ace['RightName']} Inherite: {ace['IsInherited']}")

        if ace['IsInherited']:
            #print("Heredada")
            if ace['InheritanceHash'] in result['domains_hashes']:
                #print(f"Origen Domain: {result['domains_hashes'][ace['InheritanceHash']]}")
                originType = "Domain"
                origin=result['domains_hashes'][ace['InheritanceHash']]
            elif ace['InheritanceHash'] in result['ous_hashes']:
                #print(f"Origen OU: {result['ous_hashes'][ace['InheritanceHash']]}")
                originType = "OU"
                for ou in result['ous_hashes'][ace['InheritanceHash']]:
                    if 'distinguishedname' in destination['Properties']:
                        if ou in destination['Properties']['distinguishedname']:
                            origin=ou
                    else:
                        continue
            else:
                print(f"Hash no encontrado en Domain/OU: {ace['InheritanceHash']}")
                originType = "NA"
                origin = ace['InheritanceHash']
                name = "NA"
        else:
            #print("No heredada")
            origin = ace['InheritanceHash']

        results.append({'type':ace['PrincipalType'], 'name':name,'PrincipalSID':ace['PrincipalSID'], 'RightName':ace['RightName'], 'IsInherited':ace['IsInherited'], 'sourceType':ace['PrincipalType'], 'origin':origin})


    return results


# ---------------------------------------------------------------------------
# Phase 1 · Collect
# ---------------------------------------------------------------------------
STATE = {}   # keeps client / raw json for the investigation helpers


def _enrich(client, df_users, df_groups):
    """Metrics, normalisation and the weighted risk score (verbatim logic from the original menu)."""
    #Cleaning errors in users
    if "objectid" in df_users.columns:
        df_users = df_users.dropna(subset=['objectid'])
    df_users = df_users[~df_users['whencreated'].isna()]

    #Cleaning errors in groups
    if "objectid" in df_groups.columns:
        df_groups = df_groups.dropna(subset=['objectid'])

    #Tier zero
    df_groups['admin_tier_0'] = df_groups['system_tags'].str.contains('admin_tier_0')
    df_groups['admin_tier_0'] = df_groups['admin_tier_0'].fillna(False)

    df_users["controllables_norm"]=(df_users["controllables"]-df_users["controllables"].min())/(df_users["controllables"].max()-df_users["controllables"].min())
    df_users["controllers_norm"]=(df_users["controllers"]-df_users["controllers"].min())/(df_users["controllers"].max()-df_users["controllers"].min())
    df_users["path_da_nedges_norm"]=(df_users["path_da_nedges"]-df_users["path_da_nedges"].min())/(df_users["path_da_nedges"].max()-df_users["path_da_nedges"].min())
    df_users["sessions_norm"]=(df_users["sessions"]-df_users["sessions"].min())/(df_users["sessions"].max()-df_users["sessions"].min())


    df_groups["controllables_norm"]=(df_groups["controllables"]-df_groups["controllables"].min())/(df_groups["controllables"].max()-df_groups["controllables"].min())
    df_groups["controllers_norm"]=(df_groups["controllers"]-df_groups["controllers"].min())/(df_groups["controllers"].max()-df_groups["controllers"].min())
    df_groups["path_da_nedges_norm"]=(df_groups["path_da_nedges"]-df_groups["path_da_nedges"].min())/(df_groups["path_da_nedges"].max()-df_groups["path_da_nedges"].min())
    df_groups["members_norm"]=(df_groups["members"]-df_groups["members"].min())/(df_groups["members"].max()-df_groups["members"].min())
    df_groups["sessions_norm"]=(df_groups["sessions"]-df_groups["sessions"].min())/(df_groups["sessions"].max()-df_groups["sessions"].min())

    #In path to DA
    uniq_nodes = {}
    for index, row in df_users.iterrows():
        for e in row["path_da_nodes_oidlist"]:
            if e in uniq_nodes:
                uniq_nodes[e] = uniq_nodes[e]+1
            else:
                uniq_nodes[e] = 1

    for index, row in df_groups.iterrows():
        for e in row["path_da_nodes_oidlist"]:
            if e in uniq_nodes:
                uniq_nodes[e] = uniq_nodes[e]+1
            else:
                uniq_nodes[e] = 1

    df_users["n_in_path_da"]= df_users["objectid"].map(uniq_nodes)
    df_users['n_in_path_da'] = df_users['n_in_path_da'].fillna(0)
    df_users["n_in_path_da_norm"]=(df_users["n_in_path_da"]-df_users["n_in_path_da"].min())/(df_users["n_in_path_da"].max()-df_users["n_in_path_da"].min())

    df_groups["n_in_path_da"]= df_groups["objectid"].map(uniq_nodes)
    df_groups['n_in_path_da'] = df_groups['n_in_path_da'].fillna(0)
    df_groups["n_in_path_da_norm"]=(df_groups["n_in_path_da"]-df_groups["n_in_path_da"].min())/(df_groups["n_in_path_da"].max()-df_groups["n_in_path_da"].min())

    # Groups - Mean users controllables - group controllables
    from certeu_utils import get_group_members

    df_users_controllables = df_users[["objectid","controllables"]]

    with multiprocessing.Pool(processes=multiprocessing.cpu_count()-1) as pool:
        results = pool.map(get_group_members, df_groups["objectid"])
    df_groups["members_list"] = results

    def get_mem_mean(members):
        mean= df_users_controllables[df_users_controllables['objectid'].isin(members)].controllables.mean()
        return mean

    df_groups['members_controllables_mean'] = df_groups["members_list"].apply(get_mem_mean)
    df_groups['users_mean-group_control'] = df_groups['members_controllables_mean'] - df_groups['controllables']
    df_groups["users_mean-group_control_norm"] = 1 - ((df_groups["users_mean-group_control"] - df_groups["users_mean-group_control"].min()) / (df_groups["users_mean-group_control"].max() - df_groups["users_mean-group_control"].min()))
    df_groups["users_mean-group_control_norm"].fillna(0, inplace=True)

    df_groups = df_groups.drop(columns=['members_list'])

    #Risk
    ##Users
    df_users["control_risk"] = (df_users["controllables"]) + (df_users["controllers"]) + (df_users["path_da_nedges"]) + (df_users["n_in_path_da"]) + (df_users["sessions"])
    df_users["control_risk_norm"] = (df_users["controllables_norm"]*1) + (df_users["controllers_norm"]*1) + (df_users["path_da_nedges_norm"]*1) + (df_users["n_in_path_da_norm"]*1)+ (df_users["sessions_norm"]*1)
    total_risk_norm_users = df_users['control_risk_norm'].sum()
    df_users['control_risk_norm_100'] = ((df_users['control_risk_norm'] / total_risk_norm_users) * 100)
    total_risk_users = df_users['control_risk'].sum()
    df_users['control_risk_100'] = (df_users['control_risk'] / total_risk_users) * 100
    ##Groups
    df_groups["control_risk"] = (df_groups["controllables"]) + (df_groups["controllers"]) + (df_groups["path_da_nedges"]) + (df_groups["members"]) + (df_groups["n_in_path_da"]) + (df_groups["sessions"])
    df_groups["control_risk_norm"] = (df_groups["controllables_norm"]*1) + (df_groups["controllers_norm"]*1) + (df_groups["path_da_nedges_norm"]*1) + (df_groups["members_norm"]*1) + (df_groups["n_in_path_da_norm"]*1) + (df_groups["users_mean-group_control_norm"]*1) + (df_groups["sessions_norm"]*1)
    total_risk_norm_groups = df_groups['control_risk_norm'].sum()
    df_groups['control_risk_norm_100'] = ((df_groups['control_risk_norm'] / total_risk_norm_groups) * 100)
    total_risk_groups = df_groups['control_risk'].sum()
    df_groups['control_risk_100'] = (df_groups['control_risk'] / total_risk_groups) * 100



    return df_users, df_groups


def collect(folder, host, token_id, token_key, port=8080, scheme="http", use_saved=False):
    """Process a SharpHound folder through BloodHound CE. Returns (df_users, df_groups) and saves users.csv / groups.csv."""
    t0 = time()
    data = processBHfolder(folder) if folder and os.path.isdir(folder) else {}
    if data:
        print(f"→ Reading SharpHound JSON from {folder}")
        processed, df_users_init, df_groups_init = processData(data)
        STATE.update(rawdata_json=data, processed_json=processed)
    elif not use_saved:
        raise FileNotFoundError(f"No SharpHound JSON files found in {folder!r}")
    else:
        print("→ No SharpHound folder selected — rights_origin() will not be available")

    if use_saved and os.path.exists("users.csv") and os.path.exists("groups.csv"):
        print("→ Loading users.csv / groups.csv from a previous run (BloodHound not needed)")
        df_users, df_groups = pd.read_csv("users.csv"), pd.read_csv("groups.csv")
        try:
            STATE["client"] = bh_connect(token_id, token_key, scheme, host, port)
        except Exception:
            pass
    else:
        print("→ Connecting to BloodHound CE")
        client = bh_connect(token_id, token_key, scheme, host, port)
        STATE["client"] = client
        domains = client.get_domains_ids()
        print("→ Enriching users (this is the slow part)")
        df_users = process_usersv2(client, domains, df_users_init)
        print("→ Enriching groups")
        df_groups = process_groupsv2(client, domains, df_groups_init)
        df_users, df_groups = _enrich(client, df_users, df_groups)
        df_users.to_csv("users.csv", index=False); df_groups.to_csv("groups.csv", index=False)
        print("→ Saved users.csv and groups.csv")

    print(f"✓ {len(df_users)} users · {len(df_groups)} groups · {datetime.timedelta(seconds=int(time()-t0))}")
    return df_users, df_groups


def load_saved(users="users.csv", groups="groups.csv"):
    """Reload a previous run without touching BloodHound."""
    df_users, df_groups = pd.read_csv(users), pd.read_csv(groups)
    if "users_mean-group_control_norm" not in df_groups.columns:
        print("⚠️  'users_mean-group_control_norm' missing — filling with 0 (older CSV).")
        df_groups["users_mean-group_control_norm"] = 0.0
    print(f"✓ {len(df_users)} users · {len(df_groups)} groups · "
          f"{int((df_users['path_da_nedges'] > 0).sum())} users with a path to Domain Admins")
    return df_users, df_groups


def config_menu():
    """Widget form for the live demo. Press *Process data*; results land in the notebook as df_users / df_groups."""
    import ipywidgets as w
    from ipyfilechooser import FileChooser
    host = w.Text(value="localhost", description="BloodHound host:", style={"description_width": "initial"})
    port = w.BoundedIntText(value=8080, max=65535, description="Port:", style={"description_width": "initial"})
    scheme = w.Dropdown(options=["http", "https"], value="http", description="Scheme:", style={"description_width": "initial"})
    tid = w.Text(description="Token ID:", style={"description_width": "initial"})
    tkey = w.Password(description="Token key:", style={"description_width": "initial"})
    fc = FileChooser(); fc.show_only_dirs = True; fc.title = "<b>Folder with SharpHound JSON files</b>"
    saved = w.Checkbox(value=False, description="Use saved users.csv / groups.csv", indent=False)
    btn = w.Button(description="Process data", button_style="primary")
    out = w.Output()

    def go(_):
        with out:
            clear_output()
            try:
                df_users, df_groups = collect(fc.selected_path, host.value, tid.value, tkey.value, port.value, scheme.value, saved.value)
                ip = get_ipython()
                if ip is not None: ip.push({"df_users": df_users, "df_groups": df_groups})
                STATE["df_users"], STATE["df_groups"] = df_users, df_groups
                display(Markdown("**df_users** and **df_groups** are ready."))
            except Exception as e:
                print("✗", e)
    btn.on_click(go)
    display(w.VBox([w.HBox([host, port, scheme]), w.HBox([tid, tkey]), fc, saved, btn, out]))


# ---------------------------------------------------------------------------
# Phase 2 · Layer 1 — Risk ranking
# ---------------------------------------------------------------------------
RISK_COLS = ["name", "controllables", "controllers", "members", "path_da_nedges", "n_in_path_da", "admin_tier_0", "control_risk_norm_100"]


def risk_ranking(df, n=10, weights=None):
    """Top-N objects by the weighted, normalised risk score. `weights` re-weights the *_norm features (default: all 1)."""
    d = df.copy()
    feats = [c for c in d.columns if c.endswith("_norm") and c != "control_risk_norm"]
    if weights:
        d["control_risk_norm"] = sum(d[f].fillna(0) * weights.get(f, 1.0) for f in feats)
        d["control_risk_norm_100"] = d["control_risk_norm"] / d["control_risk_norm"].sum() * 100
    cols = [c for c in RISK_COLS if c in d.columns]
    top = d.sort_values("control_risk_norm_100", ascending=False).head(n)[cols].reset_index(drop=True)
    return (top.style
            .background_gradient(cmap="Oranges", subset=["control_risk_norm_100"])
            .format({"control_risk_norm_100": "{:.2f}"})
            .set_caption(f"Top {n} by risk score — deterministic, transparent, tunable"))


# ---------------------------------------------------------------------------
# Phase 3 · Layer 2 — Graph view
# ---------------------------------------------------------------------------
def domain_map(df, x="controllers", y="path_da_nedges", color="admin_tier_0", filter_col="control_risk_norm_100", top=200):
    """Interactive graph analysis (the widget from the original notebook): filter the top/bottom N objects by any
    column, then pick X, Y and colour. Hover shows the name. Size follows the filter column."""
    import ipywidgets as w
    import plotly.express as px
    from ipywidgets import GridspecLayout, Layout

    skip = {"objectID", "error", "whencreated", "membership", "control_risk", "control_risk_100", "lastseen"}
    num = [c for c in df.select_dtypes(include="number").columns if not c.startswith("Unnamed") and c not in skip]
    cat = [c for c in ["admin_tier_0", "admincount", "kmeans_cluster", "dbscan_cluster", "domain"] if c in df.columns]
    pick = lambda want, opts: want if want in opts else opts[0]

    f_col = w.Dropdown(options=num, value=pick(filter_col, num), description="Filter by:", style={"description_width": "initial"})
    f_ord = w.ToggleButtons(options=["Highest", "Lowest"], value="Highest", description="Keep:", button_style="info", style={"description_width": "initial"})
    f_n = w.IntSlider(value=min(top, len(df)), min=10, max=len(df), step=10, description="N objects:", continuous_update=False, style={"description_width": "initial"})
    x_w = w.Dropdown(options=num, value=pick(x, num), description="X:")
    y_w = w.Dropdown(options=num, value=pick(y, num), description="Y:")
    c_w = w.Dropdown(options=cat + num, value=pick(color, cat + num), description="Colour:")
    log_w = w.Checkbox(value=False, description="log axes", indent=False)
    btn = w.Button(description="Draw", button_style="primary")
    out = w.Output()

    def draw(_=None):
        with out:
            clear_output(wait=True)
            d = (df.nlargest if f_ord.value == "Highest" else df.nsmallest)(int(f_n.value), f_col.value).copy()
            d["short"] = d["name"].astype(str).str.split("@").str[0]
            c = c_w.value
            if c in cat: d[c] = d[c].astype(str)
            fig = px.scatter(d, x=x_w.value, y=y_w.value, color=c, hover_name="short",
                             size=d[f_col.value].clip(lower=0) + 1e-9, size_max=28, opacity=0.8,
                             hover_data={"controllables": True, "controllers": True, "members": True, "n_in_path_da": True, "control_risk_norm_100": ":.2f", "short": False},
                             color_continuous_scale=["#8892B0", "#FFD700", "#F15A29"],
                             log_x=log_w.value, log_y=log_w.value,
                             title=f"{f_ord.value} {int(f_n.value)} by {f_col.value}  ·  {x_w.value} vs {y_w.value}")
            fig.update_layout(height=560, template="plotly_dark", paper_bgcolor="#0A192F", plot_bgcolor="#112240")
            fig.show()

    btn.on_click(draw)
    g = GridspecLayout(2, 4)
    g[0, 0], g[0, 1], g[0, 2], g[0, 3] = f_col, f_ord, f_n, log_w
    g[1, 0], g[1, 1], g[1, 2], g[1, 3] = x_w, y_w, c_w, btn
    display(g, out)
    draw()


def rights_origin(name):
    """Where does an object get its rights? ACEs on it and whether they are explicit or inherited (needs collect())."""
    if "rawdata_json" not in STATE:
        print("Run collect() first — this needs the raw SharpHound JSON."); return
    res = get_user_aces(STATE["rawdata_json"], STATE["processed_json"], name.upper())
    if not res:
        print("No results"); return
    return pd.DataFrame.from_records(res)


# ---------------------------------------------------------------------------
# Phase 4 · Layer 3 — Anomaly consensus
# ---------------------------------------------------------------------------
BUILTIN_PATTERNS = [r"^USERS@", r"^DOMAIN USERS@", r"^PRE-WINDOWS 2000", r"^AUTHENTICATED USERS@", r"^EVERYONE@"]
LOG_FEATURES = ["controllables", "path_da_nedges", "n_in_path_da", "members"]
DIRECT_FEATURES = ["controllers"]
NORM_FEATURES = ["users_mean-group_control_norm"]
INTERPRET_FEATURES = ["controllables", "path_da_nedges", "n_in_path_da", "members", "controllers", "users_mean-group_control_norm"]
FEATURE_DISPLAY = {
    "controllables": "objects it controls", "controllers": "principals that control it",
    "path_da_nedges": "distance to DA", "n_in_path_da": "presence in paths to DA",
    "members": "members", "users_mean-group_control_norm": "privilege inherited by members",
}


class ML:
    """Result container for the ML layer (df is the analysis frame with all scores)."""
    def __init__(self, df, X, pca, X_pca, kmeans, dbscan, features):
        self.df, self.X, self.pca, self.X_pca, self.kmeans, self.dbscan, self.features = df, X, pca, X_pca, kmeans, dbscan, features
        self.embeddings = None


def _smart_deviation(series):
    q1, med, q3 = series.quantile([0.25, 0.5, 0.75]); iqr = q3 - q1
    return (series.rank(pct=True) - 0.5) * 16 if iqr == 0 else (series - med) / iqr


def _intensity(z):
    a = abs(z)
    return "extreme" if a >= 6 else "high" if a >= 3 else "moderate" if a >= 1.5 else "mild"


def _reasons(row, n=3):
    out = []
    for f in row.abs().sort_values(ascending=False).head(n).index:
        z = row[f]
        if abs(z) < 1.5: continue
        out.append(f"{'↑' if z > 0 else '↓'} {FEATURE_DISPLAY.get(f, f)} ({_intensity(z)}, {z:+.1f})")
    return "  ·  ".join(out) if out else "no strong deviation"


def anomaly_consensus(df_groups, contamination=0.05, eps=None, top_n=20, show=True):
    """Layer 3 end to end: RobustScaler → PCA → K-Means/DBSCAN → IF + LOF + OC-SVM → rank ensemble → explained top-N."""
    from sklearn.preprocessing import RobustScaler
    from sklearn.decomposition import PCA
    from sklearn.cluster import KMeans, DBSCAN
    from sklearn.metrics import silhouette_score
    from sklearn.neighbors import NearestNeighbors, LocalOutlierFactor
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from scipy.stats import rankdata

    # 1. features
    is_builtin = df_groups["name"].astype(str).str.contains("|".join(BUILTIN_PATTERNS), case=False, na=False, regex=True)
    df = df_groups[~is_builtin].reset_index(drop=True).copy()
    feats = pd.concat([np.log1p(df[LOG_FEATURES].fillna(0)), df[DIRECT_FEATURES].fillna(0), df[NORM_FEATURES].fillna(0)], axis=1)
    X = RobustScaler().fit_transform(feats.values)

    # 2. PCA
    pca = PCA(n_components=3, random_state=42); X_pca = pca.fit_transform(X)
    df["pc1"], df["pc2"], df["pc3"] = X_pca[:, 0], X_pca[:, 1], X_pca[:, 2]

    # 3. K-Means (k by silhouette) and DBSCAN (eps from the k-distance knee)
    best_k, best_s = 2, -1
    for k in range(2, 11):
        km = KMeans(n_clusters=k, n_init=10, random_state=42).fit(X); s = silhouette_score(X, km.labels_)
        if s > best_s: best_k, best_s = k, s
    kmeans = KMeans(n_clusters=best_k, n_init=10, random_state=42).fit(X)
    df["kmeans_cluster"] = kmeans.labels_
    df["kmeans_dist"] = np.linalg.norm(X - kmeans.cluster_centers_[kmeans.labels_], axis=1)
    k_nb = 2 * X.shape[1]
    kd = np.sort(NearestNeighbors(n_neighbors=k_nb).fit(X).kneighbors(X)[0][:, -1])
    eps = eps or float(np.quantile(kd, 0.95))
    dbscan = DBSCAN(eps=eps, min_samples=k_nb, n_jobs=-1).fit(X)
    df["dbscan_cluster"] = dbscan.labels_

    # 4. three detectors
    ifo = IsolationForest(n_estimators=200, contamination=contamination, random_state=42, n_jobs=-1).fit(X)
    df["iforest_score"] = -ifo.score_samples(X)
    lof = LocalOutlierFactor(n_neighbors=20, contamination=contamination, n_jobs=-1); lof.fit_predict(X)
    df["lof_score"] = -lof.negative_outlier_factor_
    oc = OneClassSVM(kernel="rbf", gamma="scale", nu=contamination).fit(X)
    df["ocsvm_score"] = -oc.score_samples(X)

    # 5. rank ensemble
    pr = lambda s: (rankdata(s, method="average") - 1) / (len(s) - 1)
    df["iforest_rank"], df["lof_rank"], df["ocsvm_rank"], df["kmeans_rank"] = pr(df["iforest_score"]), pr(df["lof_score"]), pr(df["ocsvm_score"]), pr(df["kmeans_dist"])
    df["dbscan_flag"] = df["dbscan_cluster"].eq(-1).astype(float)
    df["consensus_score"] = 0.25 * df["iforest_rank"] + 0.15 * df["lof_rank"] + 0.25 * df["ocsvm_rank"] + 0.20 * df["kmeans_rank"] + 0.15 * df["dbscan_flag"]

    # 6. reasons
    rz = df[INTERPRET_FEATURES].fillna(0).apply(_smart_deviation)
    df["why"] = rz.apply(_reasons, axis=1)

    ml = ML(df, X, pca, X_pca, kmeans, dbscan, list(feats.columns))
    print(f"✓ {len(df)} groups analysed (excluded {int(is_builtin.sum())} built-ins) · K-Means k={best_k} · "
          f"DBSCAN eps={eps:.2f} → {int(df['dbscan_flag'].sum())} noise points · "
          f"{int((df[['iforest_rank','lof_rank','ocsvm_rank']] > 1 - contamination).all(axis=1).sum())} flagged by all three detectors")
    if show: display(anomaly_report(ml, top_n))
    return ml


def anomaly_report(ml, top_n=20):
    """Styled top-N table: consensus score, per-detector signal and the reason in words."""
    top = ml.df.nlargest(top_n, "consensus_score")
    rep = pd.DataFrame({
        "#": range(1, len(top) + 1), "group": top["name"].astype(str).str.split("@").str[0].values,
        "tier-0": np.where(top["admin_tier_0"].astype(bool), "⭐", ""),
        "IF": top["iforest_rank"].values, "LOF": top["lof_rank"].values, "SVM": top["ocsvm_rank"].values,
        "DBSCAN": np.where(top["dbscan_flag"] == 1, "noise", ""),
        "consensus": top["consensus_score"].values, "risk": top["control_risk_norm_100"].values,
        "why": top["why"].values,
    })
    return (rep.style.hide(axis="index")
            .background_gradient(cmap="Oranges", subset=["IF", "LOF", "SVM"], vmin=0, vmax=1)
            .background_gradient(cmap="Reds", subset=["consensus"], vmin=0.5, vmax=1)
            .format({"IF": "{:.2f}", "LOF": "{:.2f}", "SVM": "{:.2f}", "consensus": "{:.3f}", "risk": "{:.2f}"})
            .set_caption(f"Top {top_n} groups by anomaly consensus — with the reason each one was flagged")
            .set_table_styles([{"selector": "th", "props": [("background-color", "#0A192F"), ("color", "white")]},
                               {"selector": "td:last-child", "props": [("font-size", "9pt"), ("max-width", "520px")]}]))


def anomaly_map(ml):
    """3D PCA space: archetypes as clusters, DBSCAN noise in orange — the candidates."""
    import plotly.express as px
    d = pd.DataFrame(ml.X_pca, columns=["PC1", "PC2", "PC3"])
    d["cluster"] = np.where(ml.df["dbscan_flag"] == 1, "noise / candidate", "cluster " + ml.df["kmeans_cluster"].astype(str))
    d["name"] = ml.df["name"].astype(str).str.split("@").str[0].values
    d["consensus"] = ml.df["consensus_score"].values
    fig = px.scatter_3d(d, x="PC1", y="PC2", z="PC3", color="cluster", hover_name="name", hover_data=["consensus"],
                        color_discrete_map={"noise / candidate": "#F15A29"}, opacity=0.75, title="The shape of the domain")
    fig.update_traces(marker=dict(size=4)); fig.update_layout(height=600, template="plotly_dark")
    fig.show()


# ---------------------------------------------------------------------------
# Phase 5 · Layer 4 — Local AI
# ---------------------------------------------------------------------------
EMBED_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EMBED_MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "all-MiniLM-L6-v2")
LLM_MODEL = "llama3.2:3b"

# Offline by default: if the model is on disk next to this file, never touch the network.
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
if os.path.isdir(EMBED_MODEL_DIR):
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"


def _load_embed_model():
    """Local folder first (100 % offline); fall back to the Hub only if the folder is missing."""
    from sentence_transformers import SentenceTransformer
    if os.path.isdir(EMBED_MODEL_DIR):
        return SentenceTransformer(EMBED_MODEL_DIR, device="cpu")
    print(f"⚠️  {EMBED_MODEL_DIR} not found — downloading {EMBED_MODEL_NAME} from Hugging Face (run prepare_offline.py once to avoid this).")
    return SentenceTransformer(EMBED_MODEL_NAME, device="cpu")
PRIV_PROMPT = ("highly privileged Active Directory administrative group with domain-wide control "
               "such as domain admins, enterprise admins, schema admins, backup operators, account operators")
NORMAL_PROMPT = ("regular business end users without administrative privileges, such as marketing, finance, "
                 "sales, interns, contractors, distribution lists, or mailing groups")


def _ensure_embeddings(ml):
    if ml.embeddings is not None: return
    ml.embed_model = _load_embed_model()
    ml.df["name_for_embedding"] = ml.df["name"].astype(str).str.split("@").str[0].str.replace("-", " ").str.replace("_", " ")
    ml.embeddings = ml.embed_model.encode(ml.df["name_for_embedding"].tolist(), batch_size=32, convert_to_numpy=True, show_progress_bar=False).astype(np.float32)


def semantic_search(ml, query, top_n=8):
    """Ask the directory in plain language. Describe what you WANT — embeddings do not understand negation."""
    from sklearn.metrics.pairwise import cosine_similarity
    _ensure_embeddings(ml)
    q = ml.embed_model.encode(query, convert_to_numpy=True).reshape(1, -1)
    sims = cosine_similarity(q, ml.embeddings)[0]
    d = ml.df.assign(similarity=sims).nlargest(top_n, "similarity")
    out = d[["name", "similarity", "controllables", "n_in_path_da", "consensus_score"]].copy()
    out["name"] = out["name"].astype(str).str.split("@").str[0]
    return (out.reset_index(drop=True).style.hide(axis="index")
            .background_gradient(cmap="Blues", subset=["similarity"]).background_gradient(cmap="Oranges", subset=["consensus_score"])
            .format({"similarity": "{:.2f}", "consensus_score": "{:.2f}"}).set_caption(f"🔍 {query}"))


def incoherence(ml, n=10, min_consensus=0.75, max_name_rank=0.8, show_inverse=True):
    """The liars: observed risk (ML) minus expected risk (name). High → dangerous metrics under a harmless name.
    Groups BloodHound tags as tier-0, or whose name already sounds privileged, are expected — they are listed apart as validation."""
    from sklearn.metrics.pairwise import cosine_similarity
    _ensure_embeddings(ml)
    pv = ml.embed_model.encode(PRIV_PROMPT, convert_to_numpy=True).reshape(1, -1)
    nv = ml.embed_model.encode(NORMAL_PROMPT, convert_to_numpy=True).reshape(1, -1)
    ml.df["sim_privileged"] = cosine_similarity(ml.embeddings, pv).flatten()
    ml.df["sim_normal"] = cosine_similarity(ml.embeddings, nv).flatten()
    ml.df["name_privilege_rank"] = (ml.df["sim_privileged"] - ml.df["sim_normal"]).rank(pct=True)
    ml.df["incoherence_score"] = ml.df["consensus_score"] - ml.df["name_privilege_rank"]

    short = lambda d: d.assign(name=d["name"].astype(str).str.split("@").str[0]).reset_index(drop=True)
    fmt = {"consensus_score": "{:.2f}", "name_privilege_rank": "{:.2f}", "incoherence_score": "{:+.2f}"}
    tier0 = ml.df["admin_tier_0"].fillna(False).astype(bool)
    anomalous = ml.df["consensus_score"] > min_consensus

    # (a) expected: tier-0 the pipeline found on its own — validation, not a finding
    exp = ml.df[anomalous & tier0].nlargest(n, "consensus_score")[["name", "consensus_score", "name_privilege_rank", "controllables", "n_in_path_da"]]
    display(short(exp).style.hide(axis="index").background_gradient(cmap="Greens", subset=["consensus_score"]).format(fmt)
            .set_caption(f"✅ EXPECTED — {int((anomalous & tier0).sum())} tier-0 groups flagged as anomalous: the pipeline finds the real admins (validation)"))

    # (b) the liars: anomalous, not tier-0, and the name does not sound privileged
    cols = ["name", "consensus_score", "name_privilege_rank", "incoherence_score", "controllables", "controllers", "n_in_path_da", "members"]
    cand = ml.df[anomalous & ~tier0 & (ml.df["name_privilege_rank"] < max_name_rank)]
    ml.top_misconfigs = cand.nlargest(n, "incoherence_score")[cols + ["admin_tier_0"]].copy()
    display(short(ml.top_misconfigs[cols]).style.hide(axis="index")
            .background_gradient(cmap="Reds", subset=["incoherence_score"]).background_gradient(cmap="Oranges", subset=["consensus_score"])
            .background_gradient(cmap="Blues_r", subset=["name_privilege_rank"]).format(fmt)
            .set_caption("🚨 THE LIARS — harmless name, dangerous metrics (red = anomalous · dark blue = name sounds harmless)"))

    # (c) the inverse: scary name, quiet metrics
    if show_inverse:
        inv = ml.df[~tier0].nsmallest(n, "incoherence_score")[["name", "consensus_score", "name_privilege_rank", "incoherence_score", "controllables", "n_in_path_da"]]
        display(short(inv).style.hide(axis="index").background_gradient(cmap="Blues", subset=["name_privilege_rank"])
                .background_gradient(cmap="Greys", subset=["consensus_score"]).format(fmt)
                .set_caption("ℹ️  Scary name, quiet metrics — forgotten or legacy, low priority"))


def _llm_prompt(row):
    return f"""You are an Active Directory security analyst. A group has been flagged as a potential misconfiguration because its name doesn't match its privilege level.

Group name: {row['name']}
Metrics:
- Controls {int(row['controllables'])} objects in the domain
- Can be modified by {int(row['controllers'])} principals
- Has {int(row['members'])} members
- Appears in {int(row['n_in_path_da'])} attack paths to Domain Admin
- Is explicitly marked as tier-0: {bool(row['admin_tier_0'])}

ML anomaly score (0-1, higher = more anomalous): {row['consensus_score']:.2f}
Semantic expectation from name (0-1, higher = sounds privileged): {row['name_privilege_rank']:.2f}

Answer in 3 short sentences:
1. Does this group's privilege level match what its name suggests? Why? Mention every metric that looks dangerous.
2. What's the most likely explanation (legitimate tier-0, misconfiguration, legacy, etc.)?
3. What's your recommended action (review now, monitor, ignore)?

Keep it concise and direct."""


def llm_explain(ml, n=3, model=LLM_MODEL):
    """Ask a local LLM (Ollama) to explain the top-N liars in the analyst's language. Nothing leaves the machine."""
    import ollama
    try:
        names = [m.get("model") or m.get("name") for m in ollama.list().get("models", [])]
    except Exception as e:
        raise ConnectionError(f"Ollama is not reachable on localhost:11434 — start it with `ollama serve` ({e})")
    if not any(str(n).startswith(model.split(":")[0]) for n in names):
        raise FileNotFoundError(f"Model {model!r} not found in Ollama — run `ollama pull {model}` once (needs internet), then it is fully offline.")
    if not hasattr(ml, "top_misconfigs"): incoherence(ml, show_inverse=False)
    rows = []
    for _, r in tqdm(ml.top_misconfigs.head(n).iterrows(), total=n, desc=model):
        full = ml.df.loc[ml.df["name"] == r["name"]].iloc[0]
        ans = ollama.chat(model=model, messages=[{"role": "user", "content": _llm_prompt(full)}], options={"temperature": 0.3})["message"]["content"].strip()
        rows.append({"group": str(r["name"]).split("@")[0], "consensus": f"{r['consensus_score']:.2f}",
                     "sounds privileged": f"{r['name_privilege_rank']:.2f}", "incoherence": f"{r['incoherence_score']:+.2f}", "LLM analysis": ans})
    rep = pd.DataFrame(rows)
    return (rep.style.hide(axis="index").set_caption(f"🤖 Local LLM report — {model}")
            .set_table_styles([{"selector": "th", "props": [("background-color", "#0A192F"), ("color", "white"), ("text-align", "left")]},
                               {"selector": "td", "props": [("vertical-align", "top"), ("padding", "8px")]},
                               {"selector": "td:last-child", "props": [("max-width", "560px"), ("font-size", "10pt"), ("line-height", "1.5")]}]))

# ---------------------------------------------------------------------------
# Phase 6 · Full circle — inspect one group through all four layers
# ---------------------------------------------------------------------------
def _gauge_html(label, value, lo_is_good=True, note=""):
    """A small horizontal meter: 0..1 value, coloured green→orange→red."""
    v = 0.0 if value is None or (isinstance(value, float) and np.isnan(value)) else float(max(0, min(1, value)))
    col = "#3DDC97" if v < 0.4 else "#FFD700" if v < 0.7 else "#F15A29"
    if not lo_is_good: col = "#8892B0"
    return f"""
    <div style="flex:1;min-width:180px;background:#112240;border:1px solid #233554;border-radius:8px;padding:12px 14px">
      <div style="font-family:Courier New,monospace;font-size:10px;letter-spacing:2px;color:#8892B0">{label}</div>
      <div style="font-family:Arial;font-size:30px;font-weight:bold;color:{col};line-height:1.2">{v:.2f}</div>
      <div style="height:6px;background:#0A192F;border-radius:3px;margin:6px 0"><div style="width:{v*100:.0f}%;height:6px;background:{col};border-radius:3px"></div></div>
      <div style="font-family:Arial;font-size:11px;color:#8892B0">{note}</div>
    </div>"""


def group_card(ml, name, llm=False, model=LLM_MODEL):
    """Everything the pipeline knows about one group, as an HTML card. llm=True adds the local LLM's analysis."""
    from IPython.display import HTML
    df = ml.df
    short = df["name"].astype(str).str.split("@").str[0]
    hit = df[short.str.upper() == name.upper()]
    if hit.empty: hit = df[short.str.upper().str.contains(name.upper(), regex=False)]
    if hit.empty: return HTML(f"<p style='color:#F15A29;font-family:Arial'>No group matching <b>{name}</b></p>")
    r = hit.sort_values("consensus_score", ascending=False).iloc[0]
    if "name_privilege_rank" not in df.columns or pd.isna(r.get("name_privilege_rank", np.nan)):
        incoherence(ml, show_inverse=False); r = ml.df.loc[r.name]
    gname = str(r["name"]).split("@")[0]
    tier0 = bool(r.get("admin_tier_0", False))
    risk = float(r["control_risk_norm_100"]) / max(float(df["control_risk_norm_100"].max()), 1e-9)   # relative to the top of the domain
    inc = float(r["incoherence_score"]); inc01 = max(0.0, min(1.0, (inc + 1) / 2))
    verdict = ("✅ EXPECTED — tier-0 by design" if tier0 else
               "🚨 LIAR — harmless name, dangerous metrics" if (r["consensus_score"] > 0.75 and inc > 0.15) else
               "ℹ️ SCARY NAME, QUIET METRICS" if inc < -0.4 else
               "🟢 COHERENT — name and privileges agree")
    vcol = "#3DDC97" if verdict.startswith(("✅", "🟢")) else "#F15A29" if verdict.startswith("🚨") else "#8892B0"
    metrics = "".join(f"<span style='display:inline-block;margin:4px 10px 0 0;font-family:Courier New,monospace;font-size:11px;color:#CCD6F6'><span style='color:#8892B0'>{k}</span> {int(r[k]) if k != 'path_da_nedges' or True else r[k]}</span>"
                      for k in ["controllables", "controllers", "members", "path_da_nedges", "n_in_path_da"] if k in r)
    llm_html = ""
    if llm:
        try:
            import ollama
            ans = ollama.chat(model=model, messages=[{"role": "user", "content": _llm_prompt(r)}], options={"temperature": 0.3})["message"]["content"].strip()
        except Exception as e:
            ans = f"(local LLM unavailable: {e})"
        llm_html = f"""<div style="margin-top:14px;background:#060F1E;border:1px solid #233554;border-radius:8px;padding:14px">
           <div style="font-family:Courier New,monospace;font-size:10px;letter-spacing:2px;color:#F15A29">// LOCAL LLM · {model} · nothing leaves this machine</div>
           <div style="font-family:Arial;font-size:13px;color:#CCD6F6;line-height:1.55;margin-top:8px;white-space:pre-wrap">{ans}</div></div>"""
    html = f"""
    <div style="background:#0A192F;border-radius:10px;padding:18px 20px;color:#CCD6F6;max-width:980px">
      <div style="font-family:Courier New,monospace;font-size:10px;letter-spacing:2px;color:#F15A29">// GROUP INSPECTOR</div>
      <div style="display:flex;align-items:baseline;gap:16px;flex-wrap:wrap">
        <div style="font-family:Courier New,monospace;font-size:26px;font-weight:bold;color:#FFFFFF">{gname}</div>
        <div style="font-family:Arial;font-size:13px;font-weight:bold;color:{vcol}">{verdict}</div>
      </div>
      <div>{metrics}</div>
      <div style="display:flex;gap:12px;margin-top:14px;flex-wrap:wrap">
        {_gauge_html("LAYER 1 · RISK SCORE", risk, note=f"{float(r['control_risk_norm_100']):.2f} — relative to the most risky object in the domain")}
        {_gauge_html("LAYER 3 · ANOMALY CONSENSUS", float(r['consensus_score']), note="IF · LOF · SVM · K-Means · DBSCAN agree")}
        {_gauge_html("LAYER 4 · INCOHERENCE", inc01, note=f"{inc:+.2f} — observed risk − what the name suggests (sounds privileged: {float(r['name_privilege_rank']):.2f})")}
      </div>
      <div style="margin-top:14px;font-family:Arial;font-size:12.5px;color:#8892B0"><b style="color:#CCD6F6">Why the ML flagged it:</b> {r.get('why', '')}</div>
      {llm_html}
    </div>"""
    return HTML(html)


def inspect(ml, model=LLM_MODEL):
    """Search box: type a group name, get the full-circle card. Tick 'Ask the local LLM' for the written analysis."""
    import ipywidgets as w
    names = sorted(ml.df["name"].astype(str).str.split("@").str[0].unique().tolist())
    box = w.Combobox(placeholder="type a group name…", options=names, description="Group:", ensure_option=False, layout=w.Layout(width="420px"))
    ask = w.Checkbox(value=False, description="Ask the local LLM", indent=False)
    btn = w.Button(description="Inspect", button_style="primary")
    out = w.Output()

    def go(_=None):
        if not box.value: return
        with out:
            clear_output(wait=True)
            display(group_card(ml, box.value, llm=ask.value, model=model))
    btn.on_click(go); box.on_submit(go) if hasattr(box, "on_submit") else None
    display(w.HBox([box, ask, btn]), out)
