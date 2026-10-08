import requests 
import hmac
import hashlib
import base64
import datetime
import urllib.parse
import pandas as pd
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def format_url(uri: str) -> str:
    scheme = "http"
    host = ""
    port = 8080
    formatted_uri = uri
    if uri.startswith("/"):
        formatted_uri = formatted_uri[1:]

    return f"{scheme}://{host}:{port}/{formatted_uri}"
    
def create_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=5,  # Reintentar hasta 5 veces
        backoff_factor=0.5,  # 0.5s, 1s, 2s, 4s, 8s
        status_forcelist=[429, 500, 502, 503, 504],  # Códigos que ameritan reintento
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def req(session, method: str, uri: str, body = None):
    token_id = ""
    token_key = ""
    digester = hmac.new(token_key.encode(), None, hashlib.sha256)
    digester.update(f"{method}{uri}".encode())

    # Update the digester for further chaining
    digester = hmac.new(digester.digest(), None, hashlib.sha256)

    datetime_formatted = datetime.datetime.now().astimezone().isoformat("T")
    digester.update(datetime_formatted[:13].encode())

    # Update the digester for further chaining
    digester = hmac.new(digester.digest(), None, hashlib.sha256)

    if body is not None:
        digester.update(json.dumps(body).encode('utf-8'))
    
    try:
        response = session.request(
            method=method,
            url=format_url(uri),
            headers={
                "User-Agent": "bhe-python-sdk 0002",
                "prefer": "60",
                "Authorization": f"bhesignature {token_id}",
                "RequestDate": datetime_formatted,
                "Signature": base64.b64encode(digester.digest()),
                "Content-Type": "application/json"
            },
            json=body,
            timeout=10 
        )
        response.raise_for_status() 
        return response
    except:
        return None

def get_user_ncontrollables(user_id):
    session = create_session()   
    response = req(session, 'GET', '/api/v2/users/{}/controllables?limit=1'.format(user_id))
    n = response.json()['count']

    return n
    
def get_user_ncontrollers(user_id):
    session = create_session()
    response = req(session, 'GET', '/api/v2/users/{}/controllers?limit=1'.format(user_id))
    n = response.json()['count']

    return n
    
def get_group_ncontrollables(group_id):
    session = create_session()
    response = req(session, 'GET', '/api/v2/groups/{}/controllables?limit=1'.format(group_id))
    n = response.json()['count']

    return n
    
def get_group_ncontrollers(group_id):
    session = create_session()
    response = req(session, 'GET', '/api/v2/groups/{}/controllers?limit=1'.format(group_id))
    n = response.json()['count']

    return n
    
def get_user_info(user_id):
    session = create_session()
    response = req(session, 'GET', '/api/v2/users/{}'.format(user_id))
    user_info = response.json()

    return user_info
    
    
def get_user_infov2(in_row):
    session = create_session()
    response = req(session, 'GET', '/api/v2/users/{}'.format(in_row['objectID']))
    
    if response is None:
        return {"objectID": in_row["objectID"], "error": "No data"}
    
    user_info = response.json()
    
    row ={}
    if "data" in user_info:
        for key in user_info['data']:
            if not key == 'props':
                row[key] = user_info['data'][key]
            else:
                for key_props in user_info['data']['props']:
                    row[key_props] = user_info['data']['props'][key_props]
        #row = user_info.get('Properties', {}).copy()
    
    #Tier Zero
    if 'system_tags' in row:
        if 'admin_tier_0' in row['system_tags']:
            row['admin_tier_0'] = True
        else:
            row['admin_tier_0'] = False
    else:
        row['admin_tier_0'] = False
        
    #Path to Domain Admin
    path_da_nnodes, path_da_nedges, path_da_nodes, path_da_edges, path_da_nodes_oidlist = get_shortest_path_da_stats(session, in_row['objectID'])
    row["path_da_nnodes"] = path_da_nnodes
    row["path_da_nedges"] = path_da_nedges
    row["path_da_nodes"] = path_da_nodes
    row["path_da_edges"] = path_da_edges
    row["path_da_nodes_oidlist"] = path_da_nodes_oidlist
    
    
    #Risk
    if "controllables" not in row:
        row["controllables"] = 0
    if "controllers" not in row:
        row["controllers"] = 0
    if "path_da_nedges" not in row:
        row["path_da_nedges"] = 0
        
    
    #row["control_risk"] = (row["controllables"]+1) + (row["controllers"]+1) + (row["path_da_nedges"]+1)
    
    return row
    
def get_group_infov2(in_row):
    session = create_session()
    response = req(session, 'GET', '/api/v2/groups/{}'.format(in_row['objectID']))
    
    if response is None:
        return {"objectID": in_row["objectID"], "error": "No data"}
        
    group_info = response.json()
    
    row ={}
    
    if 'data' in group_info:
        for key in group_info['data']:
            if not key == 'props':
                row[key] = group_info['data'][key]
            else:
                for key_props in group_info['data']['props']:
                    row[key_props] = group_info['data']['props'][key_props]
        #row = group_info.get('Properties', {}).copy()
    
    #Tier Zero
    if 'system_tags' in row:
        if 'admin_tier_0' in row['system_tags']:
            row['admin_tier_0'] = True
        else:
            row['admin_tier_0'] = False
    else:
        row['admin_tier_0'] = False
        
    #Path to Domain Admin
    path_da_nnodes, path_da_nedges, path_da_nodes, path_da_edges, path_da_nodes_oidlist  = get_shortest_path_da_stats(session, in_row['objectID'])
    row["path_da_nnodes"] = path_da_nnodes
    row["path_da_nedges"] = path_da_nedges
    row["path_da_nodes"] = path_da_nodes
    row["path_da_edges"] = path_da_edges
    row["path_da_nodes_oidlist"] = path_da_nodes_oidlist
    
    if "controllables" not in row:
        row["controllables"] = 0
    if "controllers" not in row:
        row["controllers"] = 0
    if "path_da_nedges" not in row:
        row["path_da_nedges"] = 0
    if "members" not in row:
        row["members"] = 0
    
    #Risk
    row["control_risk"] = (row["controllables"]+1) + (row["controllers"]+1) + (row["path_da_nedges"]+1) + (row["members"]+1)
    
    return row
    
def get_group_members(groupID):
    session = create_session()
    limit = 100000
    response = req(session, 'GET', '/api/v2/groups/{}/members?limit={}'.format(groupID, limit))
    if response is None:
        return []
    group_info = response.json()
    if "data" in group_info:
        members = group_info["data"]
    else:
        #print("No data in get_group_members:")
        members = []
    uids_members = []
    
    for member in members:
        uids_members.append(member['objectID'])
    
    return uids_members
    
def get_group_members_std(args):
    session = create_session()
    df_users_controllables, groupID = args
    limit = 100000
    response = req(session, 'GET', '/api/v2/groups/{}/members?limit={}'.format(groupID, limit))
    if response is None:
        return []
    group_info = response.json()
    members = group_info["data"]
    
    uids_members = []
    
    for member in members:
        uids_members.append(member['objectID'])
        
    members_controllables_std = df_users_controllables[df_users_controllables['objectid'].isin(uids_members)].controllables.std()
    
    return members_controllables_std
    
def get_shortest_path_da_stats(session, start_node: str, end_node:str="") -> pd.DataFrame:
    session = create_session()
    relationship_kinds = urllib.parse.quote("in:Owns,GenericAll,GenericWrite,WriteOwner,WriteDacl,MemberOf,ForceChangePassword,AllExtendedRights,AddMember,HasSession,Contains,GPLink,AllowedToDelegate,TrustedBy,AllowedToAct,AdminTo,CanPSRemote,ExecuteDCOM,HasSIDHistory,AddSelf,DCSync,ReadLAPSPassword,ReadGMSAPassword,DumpSMSAPassword,SQLAdmin,AddAllowedToAct,WriteSPN,AddKeyCredentialLink,SyncLAPSPassword,WriteAccountRestrictions")
    
    if not end_node:
        end_node = "-".join(start_node.split("-")[:-1])+"-512"
    
    response = req(session, 'GET', f'/api/v2/graphs/shortest-path?start_node={start_node}&end_node={end_node}&relationship_kinds={relationship_kinds}')

    
    if response is None:
        path_da_nnodes = 0
        path_da_nedges = 0
        path_da_nodes = 0
        path_da_nodes_oidlist = []
        path_da_edges = 0
        
        return path_da_nnodes, path_da_nedges, path_da_nodes, path_da_edges, path_da_nodes_oidlist
        
    response_json = response.json()
    
    
    if 'data' in response_json:
        payload = response.json()['data']
        
        nodes = []
        edges = []
        
        for key in payload["nodes"].keys():
            temp = payload["nodes"][key]
            temp["id"] = key
            nodes.append(temp) #    nodes.append(data["nodes"][d])
        
        for d in payload["edges"]:
            edges.append(d)
        path_da_nodes = pd.DataFrame.from_records(nodes, index="id")
        path_da_nodes_oidlist = path_da_nodes.objectId.values
        path_da_nnodes = len(path_da_nodes)
        path_da_edges = pd.DataFrame.from_records(edges)
        #path_da_edges_oidlist = path_da_edges.objectId.values
        path_da_nedges = len(path_da_edges)
        
    elif 'Path not found' in response_json['errors'][0]['message']:
        path_da_nnodes = 0
        path_da_nedges = 0
        path_da_nodes = 0
        path_da_nodes_oidlist = []
        path_da_edges = 0
        
    elif 'not found' in response_json['errors'][0]['message']:
        path_da_nnodes = 0
        path_da_nedges = 0
        path_da_nodes = 0
        path_da_nodes_oidlist = []
        path_da_edges = 0
    else:
        print(response_json)
        path_da_nnodes = 1
        path_da_nedges = 1
        path_da_nodes = 0
        path_da_nodes_oidlist = []
        path_da_edges = 0
        #raise Exception(start_node + " " + end_node) 

    return path_da_nnodes, path_da_nedges, path_da_nodes, path_da_edges, path_da_nodes_oidlist 