from base64 import b64decode
from src.common.ExtensiveRoleCheck import rolechecker
import os
import json


sa_secrets = []


def services(data, driver):
    for service in data["services"]["items"]:
        if 'ports' not in service["spec"]:
             service["spec"]["ports"] = None
        if service["spec"]["type"] == "LoadBalancer":
            lbip = None
            if 'loadBalancerIP' in service["spec"]:
                lbip = service["spec"]["loadBalancerIP"]
            elif 'ingress' in service["status"]["loadBalancer"]:
                ingress = service["status"]["loadBalancer"]["ingress"][0]
                if "ip" in ingress:
                    lbip = ingress["ip"]
                elif "hostname" in ingress:
                    lbip = ingress["hostname"]

            query = """
            CREATE (s:Services { Name : $name, Type : $type, Namespace : $ns, ClusterIP : $clusterip, 
            LoadBalancerIP : $lbip, Ports : $ports, Selector : $selector})
            """
            driver.execute_query(query,
                                 name=service["metadata"]["name"],
                                 type=service["spec"]["type"],
                                 ns=service["metadata"]["namespace"],
                                 clusterip=service["spec"]["clusterIP"] if "clusterIP" in service["spec"] else None,
                                 lbip=lbip,
                                 selector=json.dumps(service["spec"].get("selector", {}), indent=2),
                                 ports=json.dumps(service["spec"]["ports"][0], indent=2))

        else:
            if 'selector' in service["spec"]:
                query = """
                CREATE (s:Services { Name : $name, Type : $type, Namespace : $ns, ClusterIP : $clusterip, 
                Ports : $ports, Selector : $selector})
                """
                driver.execute_query(query,
                                     name=service["metadata"]["name"],
                                     type=service["spec"]["type"],
                                     ns=service["metadata"]["namespace"],
                                     clusterip=service["spec"]["clusterIP"] if "clusterIP" in service["spec"] else None,
                                     selector=json.dumps(service["spec"].get("selector", {})),
                                     ports=json.dumps(service["spec"]["ports"], indent=2))
            else:
                query = """
                CREATE (s:Services { Name : $name, Type : $type, Namespace : $ns, ClusterIP : $clusterip, 
                Ports : $ports})
                """
                driver.execute_query(query,
                                     name=service["metadata"]["name"],
                                     type=service["spec"]["type"],
                                     ns=service["metadata"]["namespace"],
                                     clusterip=service["spec"]["clusterIP"] if "clusterIP" in service["spec"] else None,
                                     ports=json.dumps(service["spec"]["ports"], indent=2))


def nodes(data, driver):
    for node in data["nodes"]["items"]:
        master_tag = False
        for label in node["metadata"]["labels"].keys():
            if label == "node-role.kubernetes.io/control-plane":
                master_tag = True
            if label == "is_control":
                if node["metadata"]["labels"][label] == "true":
                    master_tag = True
        if master_tag:
            query = """
            CREATE (n:Nodes { Name : $name, Type : "control-plane" })
            """
        else:
            query = """
            CREATE (n:Nodes { Name : $name, Type : "worker" })
            """
        driver.execute_query(query, name=node["metadata"]["name"])


def pods(data, driver):
    sensitive_mounts = ["/var/run", "/", "/etc", "/var", "/proc", "/run", "/root", "/var/log"]
    bad_caps = ["SYS_ADMIN", "DAC_OVERRIDE", "SETGID", "SETUID", "SETPCAP", "SYS_PTRACE", "SYS_MODULE"]
    for pod in data["pods"]["items"]:
        privileged = False
        bad_mounts = []
        images = []
        caps = []
        for ctr in pod["spec"]["containers"]:
            try:
                if ctr["securityContext"]["privileged"]:
                    privileged = True
            except KeyError:
                pass
            images.append(ctr["image"])
            try:
                for cap in ctr["securityContext"]["capabilities"]["add"]:
                    if cap in bad_caps:
                        caps.append(cap)
            except KeyError:
                pass
        if pod["spec"].get("serviceAccount") is None:
            pod["spec"]["serviceAccount"] = None
        try:
            for volume in pod["spec"]["volumes"]:
                for mount in sensitive_mounts:
                    try:
                        if mount == volume["hostPath"]["path"]:
                            bad_mounts.append(volume["hostPath"]["path"])
                    except KeyError:
                        pass
        except:
            pass
        if pod["metadata"].get("labels") is None:
            pod["metadata"]["labels"] = None
        if len(caps) == 0:
            caps = None
        if bad_mounts:
            query = """
            CREATE(p:Pods {Name: $name, Namespace: $ns, serviceAccount: $sa, Images : $images, Privileged: $sc,
            nodeName : $nodeName, hostPaths : $mounts, Caps : $caps, Labels : $labels})
            """
            driver.execute_query(query, name=pod["metadata"]["name"],
                                 ns=pod["metadata"]["namespace"],
                                 sa=pod["spec"]["serviceAccount"],
                                 images=images,
                                 sc=privileged,
                                 nodeName=pod["spec"]["nodeName"],
                                 mounts=bad_mounts,
                                 caps=caps,
                                 labels=json.dumps(pod["metadata"]["labels"], indent=2))
        else:
            query = """
            CREATE(p:Pods {Name: $name, Namespace: $ns, serviceAccount: $sa, Images : $images, Privileged: $sc,
            nodeName : $nodeName, Caps : $caps, Labels : $labels})
            """
            driver.execute_query(query, name=pod["metadata"]["name"],
                                 ns=pod["metadata"]["namespace"],
                                 sa=pod["spec"]["serviceAccount"],
                                 images=images,
                                 sc=privileged,
                                 nodeName=pod["spec"]["nodeName"],
                                 caps=caps,
                                 labels=json.dumps(pod["metadata"]["labels"], indent=2))


def secrets(data, driver):
    for secret in data["secrets"]["items"]:
        sa = dict()
        try:
            query = """
            CREATE (s:Secrets { Name : $name, Type : $stype, Namespace : $ns, Data : $data, ServiceAccountName : $sa })
            """
            driver.execute_query(query, name=secret["metadata"]["name"],
                                 stype=secret["type"],
                                 ns=secret["metadata"]["namespace"],
                                 data=b64decode(secret["data"]["token"]).decode('utf-8'),
                                 sa=secret["metadata"]["annotations"]["kubernetes.io/service-account.name"])

            sa["name"] = secret["metadata"]["name"]
            sa["namespace"] = secret["metadata"]["namespace"]
            sa_secrets.append(sa)
        except KeyError:
            query = """
            CREATE (s:Secrets { Name : $name, Type : $stype, Namespace : $ns})
            """
            driver.execute_query(query, name=secret["metadata"]["name"],
                                 stype=secret["type"],
                                 ns=secret["metadata"]["namespace"],)


def clusterrolebindings(data, driver):
    verbs = []
    resources = []
    risky_roles = rolechecker(data["clusterroles"], data["roles"], sa_secrets)
    for crbs in data["clusterrolebindings"]["items"]:
        role_created = False
        if crbs.get("subjects") is None:
            crbs["subjects"] = []
            crbs["subjects"].append(dict())
            crbs["subjects"][0]["namespace"] = None
            crbs["subjects"][0]["kind"] = None
            crbs["subjects"][0]["name"] = None
        if crbs["subjects"][0].get("namespace") is None:
            crbs["subjects"][0]["namespace"] = None
        for clusterroles in data["clusterroles"]["items"]:
            if clusterroles["metadata"]["name"] == crbs["roleRef"]["name"]:
                if clusterroles["metadata"]["name"] in risky_roles:
                    query = """
                        CREATE (crb:ClusterRoleBindings { Name : $name, RoleRef_kind : $roletype, RoleRef_name : $rolename,
                        subject_kind : $skind, subject_namespace : $sns, subject_name : $sname, risky : true, 
                        risky_roles : $risky, uid : $uid, rbac : $rbac })
                        """
                    driver.execute_query(query, name=crbs["metadata"]["name"],
                                         roletype=crbs["roleRef"]["kind"],
                                         rolename=crbs["roleRef"]["name"],
                                         skind=crbs["subjects"][0]["kind"],
                                         sns=crbs["subjects"][0]["namespace"],
                                         sname=crbs["subjects"][0]["name"],
                                         risky=risky_roles[clusterroles["metadata"]["name"]],
                                         uid=crbs["metadata"]["uid"],
                                         rbac=json.dumps(clusterroles["rules"], indent=2))
                    role_created = True
                else:
                    query = """
                        CREATE (crb:ClusterRoleBindings { Name : $name, RoleRef_kind : $roletype, RoleRef_name : $rolename,
                        subject_kind : $skind, subject_namespace : $sns, subject_name : $sname, uid : $uid, rbac : $rbac })
                        """
                    driver.execute_query(query, name=crbs["metadata"]["name"],
                                         roletype=crbs["roleRef"]["kind"],
                                         rolename=crbs["roleRef"]["name"],
                                         skind=crbs["subjects"][0]["kind"],
                                         sns=crbs["subjects"][0]["namespace"],
                                         sname=crbs["subjects"][0]["name"],
                                         uid=crbs["metadata"]["uid"],
                                         rbac=json.dumps(clusterroles["rules"], indent=2))
                    role_created = True

        for roles in data["roles"]["items"]:
            if roles["metadata"]["name"] == crbs["roleRef"]["name"]:
                if roles["metadata"]["name"] in risky_roles:
                    query = """
                        CREATE (crb:ClusterRoleBindings { Name : $name, RoleRef_kind : $roletype, 
                        RoleRef_name : $rolename, subject_kind : $skind, subject_namespace : $sns, 
                        subject_name : $sname, risky : true, risky_roles : $risky, uid : $uid, rbac : $rbac })
                        """
                    driver.execute_query(query, name=crbs["metadata"]["name"],
                                         roletype=crbs["roleRef"]["kind"],
                                         rolename=crbs["roleRef"]["name"],
                                         skind=crbs["subjects"][0]["kind"],
                                         sns=crbs["subjects"][0]["namespace"],
                                         sname=crbs["subjects"][0]["name"],
                                         risky=risky_roles[roles["metadata"]["name"]],
                                         uid=crbs["metadata"]["uid"],
                                         rbac=json.dumps(roles["rules"], indent=2))
                    role_created = True
                else:
                    query = """
                        CREATE (crb:ClusterRoleBindings { Name : $name, RoleRef_kind : $roletype, 
                        RoleRef_name : $rolename, subject_kind : $skind, subject_namespace : $sns, 
                        subject_name : $sname, uid : $uid, rbac : $rbac })
                        """
                    driver.execute_query(query, name=crbs["metadata"]["name"],
                                         roletype=crbs["roleRef"]["kind"],
                                         rolename=crbs["roleRef"]["name"],
                                         skind=crbs["subjects"][0]["kind"],
                                         sns=crbs["subjects"][0]["namespace"],
                                         sname=crbs["subjects"][0]["name"],
                                         uid=crbs["metadata"]["uid"],
                                         rbac=json.dumps(roles["rules"], indent=2))
                    role_created = True

        if not role_created:
            query = """
                CREATE (crb:ClusterRoleBindings { Name : $name, RoleRef_kind : $roletype, RoleRef_name : $rolename,
                subject_kind : $skind, subject_namespace : $sns, subject_name : $sname,
                Resources : $resources, rbac : $verbs, uid : $uid, Resources : $resources })
                """
            driver.execute_query(query, name=crbs["metadata"]["name"],
                                 roletype=crbs["roleRef"]["kind"],
                                 rolename=crbs["roleRef"]["name"],
                                 skind=crbs["subjects"][0]["kind"],
                                 sns=crbs["subjects"][0]["namespace"],
                                 sname=crbs["subjects"][0]["name"],
                                 resources=resources,
                                 verbs=verbs,
                                 uid=crbs["metadata"]["uid"])


def rolebindings(data, driver):
    verbs = []
    resources = []
    risky_roles = rolechecker(data["clusterroles"], data["roles"], sa_secrets)
    for rbs in data["rolebindings"]["items"]:
        role_created = False
        if rbs.get("subjects") is None:
            rbs["subjects"] = []
            rbs["subjects"].append(dict())
            rbs["subjects"][0]["namespace"] = None
            rbs["subjects"][0]["kind"] = None
            rbs["subjects"][0]["name"] = None
        if rbs["subjects"][0].get("namespace") is None:
            rbs["subjects"][0]["namespace"] = rbs["metadata"]["namespace"]
        for roles in data["roles"]["items"]:
            if roles["metadata"]["name"] == rbs["roleRef"]["name"] and roles["metadata"]["namespace"] == rbs["subjects"][0]["namespace"]:
                if roles["metadata"]["name"] in risky_roles:
                    query = """
                        CREATE (rb:RoleBindings { Name : $name, RoleRef_kind : $roletype, RoleRef_name : $rolename,
                        subject_kind : $skind, subject_namespace : $sns, subject_name : $sname, risky : true, 
                        risky_roles : $risky, uid : $uid, rbac : $rbac, namespace : $ns })
                        """
                    driver.execute_query(query, name=rbs["metadata"]["name"],
                                         roletype=rbs["roleRef"]["kind"],
                                         rolename=rbs["roleRef"]["name"],
                                         skind=rbs["subjects"][0]["kind"],
                                         sns=rbs["subjects"][0]["namespace"],
                                         sname=rbs["subjects"][0]["name"],
                                         risky=risky_roles[roles["metadata"]["name"]],
                                         uid=rbs["metadata"]["uid"],
                                         ns=rbs["metadata"]["namespace"],
                                         rbac=json.dumps(roles["rules"], indent=2))
                else:
                    query = """
                        CREATE (rb:RoleBindings { Name : $name, RoleRef_kind : $roletype, 
                        RoleRef_name : $rolename, subject_kind : $skind, subject_namespace : $sns, 
                        subject_name : $sname, uid : $uid, rbac : $rbac, namespace : $ns })
                        """
                    driver.execute_query(query, name=rbs["metadata"]["name"],
                                         roletype=rbs["roleRef"]["kind"],
                                         rolename=rbs["roleRef"]["name"],
                                         skind=rbs["subjects"][0]["kind"],
                                         sns=rbs["subjects"][0]["namespace"],
                                         sname=rbs["subjects"][0]["name"],
                                         uid=rbs["metadata"]["uid"],
                                         ns=rbs["metadata"]["namespace"],
                                         rbac=json.dumps(roles["rules"], indent=2))
                    role_created = True

        for clusterroles in data["clusterroles"]["items"]:
            if clusterroles["metadata"]["name"] == rbs["roleRef"]["name"]:
                if clusterroles["metadata"]["name"] in risky_roles:
                    i = 0
                    sa_group_index = 0
                    if len(rbs["subjects"]) > 1:
                        while i < len(rbs["subjects"]):
                            if 'system:serviceaccounts' in rbs["subjects"][i]["name"]:
                                sa_group_index = i
                                break
                            i = i + 1
                    rbs["subjects"][sa_group_index]["namespace"] = None
                    query = """
                        CREATE (rb:RoleBindings { Name : $name, RoleRef_kind : $roletype, 
                        RoleRef_name : $rolename, subject_kind : $skind, subject_namespace : $sns, 
                        subject_name : $sname, risky : true, risky_roles : $risky, uid : $uid, rbac : $rbac,
                        namespace : $ns})
                        """
                    driver.execute_query(query, name=rbs["metadata"]["name"],
                                         roletype=rbs["roleRef"]["kind"],
                                         rolename=rbs["roleRef"]["name"],
                                         skind=rbs["subjects"][sa_group_index]["kind"],
                                         sns=rbs["subjects"][sa_group_index]["namespace"],
                                         sname=rbs["subjects"][sa_group_index]["name"],
                                         risky=risky_roles[clusterroles["metadata"]["name"]],
                                         uid=rbs["metadata"]["uid"],
                                         ns=rbs["metadata"]["namespace"],
                                         rbac=json.dumps(clusterroles["rules"], indent=2))
                    role_created = True
                else:
                    query = """
                        CREATE (rb:RoleBindings { Name : $name, RoleRef_kind : $roletype, 
                        RoleRef_name : $rolename, subject_kind : $skind, subject_namespace : $sns, 
                        subject_name : $sname, uid : $uid, rbac : $rbac, namespace : $ns })
                        """
                    driver.execute_query(query, name=rbs["metadata"]["name"],
                                         ns=rbs["metadata"]["namespace"],
                                         roletype=rbs["roleRef"]["kind"],
                                         rolename=rbs["roleRef"]["name"],
                                         skind=rbs["subjects"][0]["kind"],
                                         sns=rbs["subjects"][0]["namespace"],
                                         sname=rbs["subjects"][0]["name"],
                                         uid=rbs["metadata"]["uid"],
                                         rbac=json.dumps(clusterroles["rules"], indent=2))
                    role_created = True

        if not role_created:
            query = """
                CREATE (rb:RoleBindings { Name : $name, RoleRef_kind : $roletype, RoleRef_name : $rolename,
                subject_kind : $skind, subject_namespace : $sns, subject_name : $sname,
                Resources : $resources, rbac : $verbs, uid : $uid, Resources : $resources, namespace : $ns })
                """
            driver.execute_query(query, name=rbs["metadata"]["name"],
                                 roletype=rbs["roleRef"]["kind"],
                                 rolename=rbs["roleRef"]["name"],
                                 skind=rbs["subjects"][0]["kind"],
                                 sns=rbs["subjects"][0]["namespace"],
                                 sname=rbs["subjects"][0]["name"],
                                 resources=resources,
                                 verbs=verbs,
                                 uid=rbs["metadata"]["uid"],
                                 ns=rbs["metadata"]["namespace"])


# Load K8S objects in neo4j
def data(path, driver):
    data = {}
    files = os.listdir(path)
    for file in files:
        pathfile = path + '/' + file
        with open(pathfile) as json_file:
            object_type = file.split(".")[0]
            data[object_type] = json.load(json_file)
    nodes(data, driver)
    pods(data, driver)
    secrets(data, driver)
    clusterrolebindings(data, driver)
    rolebindings(data, driver)
    services(data, driver)



