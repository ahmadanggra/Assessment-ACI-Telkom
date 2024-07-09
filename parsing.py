import json
import requests
import re
import os
import csv

def apic_login(apic: str, username: str, password: str) -> dict:
    """ APIC login and return session cookie """
    apic_cookie = {}
    credentials = {'aaaUser': {'attributes': {'name': username, 'pwd': password }}}
    json_credentials = json.dumps(credentials)
    base_url = 'https://' + apic + '/api/aaaLogin.json'

    login_response = requests.post(base_url, data=json_credentials, verify=False)

    login_response_json = json.loads(login_response.text)
    token = login_response_json['imdata'][0]['aaaLogin']['attributes']['token']
    apic_cookie['APIC-Cookie'] = token
    return apic_cookie

def apic_query(apic: str, path: str, cookie: dict) -> dict:
    """ APIC 'GET' query and return response """
    base_url = 'https://' + apic + path

    get_response = requests.get(base_url, cookies=cookie, verify=False)

    return get_response

def apic_logout(apic: str, cookie:dict) -> dict:
    """ APIC logout and return response """
    base_url = 'https://' + apic + '/api/aaaLogout.json'

    post_response = requests.post(base_url, cookies=cookie, verify=False)

    return post_response

def getCSVPath(dest_dir: str, file_name: str) -> str:
    path_csv = str()
    location = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

    # check os if windows using \\ if not using /
    if os.name == 'nt':      
        path_csv = location + '\\' + dest_dir + '\\' + file_name
        return path_csv
    else:
        path_csv = location + '/' + dest_dir + '/' + file_name
        return path_csv

# moquery -c fvnsVlanInstP -x 'rsp-subtree=full' -o json
def parsingVLANToCsv(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/fvnsVlanInstP.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    v_name = str()
    v_list = list()
    v_domain = list()
    vlan = dict() 

    path_csv = getCSVPath('out_files', 'vlanpool.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        # writing header
        csv_writter = csv.writer(file)
        csv_writter.writerow(
            ['vlan_pool_name', 'encaps', 'domains'])
        
        # generating data from json 
        vlan_list = json.loads(response.text)
        vlan = vlan_list['imdata']
        for i in vlan:
            for j in i:
                v_name = i[j]['attributes']['name']
                #loop children
                for_k = i[j]['children']
                for k in for_k:
                    for l in k:
                        if 'fvnsEncapBlk' in k:
                            v_range = str()
                            v_from = k[l]['attributes']['from'].replace('vlan-','')
                            v_to = k[l]['attributes']['to'].replace('vlan-','')
                            if v_from == v_to:
                                v_range = v_from
                            else:
                                v_range = v_from + '-' + v_to
                            alloc = k[l]['attributes']['allocMode']
                            role = k[l]['attributes']['role']
                            #v_range = v_range + '(alloc: ' + alloc + ')' + ' (role: ' + role + ')'
                            v_list.append(v_range)
                        if 'fvnsRtVlanNs' in k:
                            v_dom_prefix = ['uni\/l3dom-','uni\/l2dom-','uni\/phys-','uni\/vmmp-VMware\/dom-']
                            v_dom_temp = k[l]['attributes']['tDn']
                            v_dom = re.sub('|'.join(sorted(v_dom_prefix, key = len, reverse = True)), '', v_dom_temp)
                            v_domain.append(v_dom)
                v_list_text = ','.join(v_list)
                v_domain_text = ','.join(v_domain)
                csv_writter.writerow([v_name,v_list_text,v_domain_text])
                v_list.clear()
                v_domain.clear()

# moquery -c fvBD -x 'rsp-subtree=full' -o json
def parsingBdToCsv(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/fvBD.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    bd = dict()

    path_csv = getCSVPath('out_files', 'bd.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        # writing header
        csv_writter = csv.writer(file)
        csv_writter.writerow(
            ['name', 'arp_flooding', 'bcast_address', 'tenant', 'unicast_route', 'l2_unknown_unicast', 'vrf', 'subnet ip', 'scope'])
        
        # generating data from json 
        bd_list = json.loads(response.text)
        bd = bd_list['imdata']        
        for i in bd:
            for j in i:
                bd_name = i[j]['attributes']['name']
                bd_arp = i[j]['attributes']['arpFlood']
                bd_bcast = i[j]['attributes']['bcastP']
                bd_tenant = i[j]['attributes']['dn'].split(
                    '/')[1].replace('tn-', '')
                bd_unicastrouting = i[j]['attributes']['unicastRoute']
                bd_l2unicast = i[j]['attributes']['unkMacUcastAct']
                bd_vrf = str()
                bd_subnet = str()
                bd_scope = str()
                for_k = i[j]['children']
                # loop children of fvBD
                for k in for_k:
                    for l in k:
                        if 'fvRsCtx' in l:
                            bd_vrf = k[l]['attributes']['tnFvCtxName']
                        if 'fvSubnet' in l:
                            bd_subnet = k[l]['attributes']['ip']
                            bd_scope = k[l]['attributes']['scope'].replace(
                                ',', ' ')
                csv_writter.writerow([bd_name, bd_arp, bd_bcast, bd_tenant,
                                     bd_unicastrouting, bd_l2unicast, bd_vrf, bd_subnet, bd_scope])

# moquery -c fvCEp -x 'rsp-subtree=full'  -o json
def parsingEpToCsv(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/fvCEp.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    endpoint = dict()
    endpoint_tenant = str()
    endpoint_ap = str()
    endpoint_epg = str()
    endpoint_mac = str()
    endpoint_leaf  = str()
    endpoint_staticport = list()
    endpoint_desc = str()
    endpoint_ip = str()
    endpoint_encapvlan = str()

    path_csv = getCSVPath('out_files', 'endpoint.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file)
        csv_writter.writerow(
            ['tenant', 'ap', 'epg', 'mac', 'ip', 'encap-vlan', 'leaf', 'static_port', 'description'])
        
        # generating data from json
        endpoint_list = json.loads(response.text)
        endpoint = endpoint_list['imdata']
        #print(endpoint)
        for i in endpoint:
            for j in i:
                endpoint_ip = i[j]['attributes']['ip']
                endpoint_encapvlan = i[j]['attributes']['encap']
                endpoint_mac = i[j]['attributes']['mac']
                for_k = i[j]['children']
                # loop children of fvCEp
                for k in for_k:
                    for l in k:
                        if 'fvRsCEpToPathEp' in l:
                            # workaround for api query sub class fvRsCEpToPathEp not returning dn
                            endpoint_data_temp = i[j]['attributes']['dn'] + '/' + k[l]['attributes']['rn']
                            endpoint_data = endpoint_data_temp.split('/')
                            # for endpoint listed as vrf endpoint
                            if 'ctx-' in endpoint_data_temp:
                                #print(endpoint_data)
                                endpoint_tenant = endpoint_data[1].replace('tn-','')
                                endpoint_ap = ''
                                endpoint_epg = endpoint_data[2].replace('ctx-','')
                                ep_leaf = ['protpaths-','paths-']
                                endpoint_leaf  = re.sub('|'.join(sorted(ep_leaf, key = len, reverse = True)), '', endpoint_data[6])
                                ep_staticport = ['pathep-','\[','\]']
                                endpoint_desc='vrf endpoint'
                                if len(endpoint_data) == 8:
                                    endpoint_staticport.append(re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[7]))
                                else:
                                    temp_endpoint_staticport = re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[7]) + '/' 
                                    temp_endpoint_staticport += re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[8])
                                    endpoint_staticport.append(temp_endpoint_staticport)                                    
                            # for endpoint category vmm
                            else:
                                #print(endpoint_data)
                                endpoint_tenant = endpoint_data[1].replace('tn-','')
                                endpoint_ap = endpoint_data[2].replace('ap-','')
                                endpoint_epg = endpoint_data[3].replace('epg-','')
                                ep_staticport = ['pathep-','pathgrp-','\[','\]']
                                # assign vmm attached leaf node
                                if 'pathgrp-' in endpoint_data_temp:
                                    leaf_len = len(k[l]['children'][0:])
                                    leaf_count = 0
                                    for leaf in k[l]['children'][0:]:
                                        if leaf_count ==0:
                                            endpoint_leaf  = leaf['fvReportingNode']['attributes']['id']
                                        else:
                                            endpoint_leaf  += '-' + leaf['fvReportingNode']['attributes']['id']
                                        leaf_count += 1
                                        if leaf_count == leaf_len:
                                            break
                                    endpoint_desc='vmm endpoint vcenter'       
                                    endpoint_staticport.append(re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[7]))
                                # assign leaf node to non vmm
                                else:
                                    ep_leaf = ['protpaths-','paths-']
                                    endpoint_leaf  = re.sub('|'.join(sorted(ep_leaf, key = len, reverse = True)), '', endpoint_data[7])
                                    endpoint_desc=''
                                    if len(endpoint_data) == 9:
                                        endpoint_staticport.append(re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[8]))
                                    else:
                                        temp_endpoint_staticport = re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[8]) + '/'
                                        temp_endpoint_staticport += re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[9])
                                        endpoint_staticport.append(temp_endpoint_staticport) 
                endpoint_staticport_string = ' '.join(endpoint_staticport)
                # for endpoint without fvRsCEpToPathEp (e.g vrf (ctx-x))
                if endpoint_tenant == '' and endpoint_ap == '' and endpoint_epg == '':
                    endpoint_tenant = endpoint_data[1].replace('tn-','')
                    endpoint_ap = ''
                    endpoint_epg = endpoint_data[2].replace('ctx-','')
                    endpoint_leaf = ''
                    endpoint_desc='vrf endpoint'

                csv_writter.writerow([endpoint_tenant, endpoint_ap,endpoint_epg,endpoint_mac,endpoint_ip,endpoint_encapvlan, endpoint_leaf,endpoint_staticport_string,endpoint_desc])
                endpoint_tenant = ''
                endpoint_ap = ''
                endpoint_epg = ''
                endpoint_mac = ''
                endpoint_leaf = ''
                endpoint_desc = ''
                endpoint_ip = ''
                endpoint_encapvlan = ''
                endpoint_staticport.clear()    

# moquery -c fvCEp -x 'rsp-subtree=full'  -o json
def parsingEpToCsv_aciv5(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/fvCEp.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    endpoint = dict()
    endpoint_tenant = str()
    endpoint_ap = str()
    endpoint_epg = str()
    endpoint_mac = str()
    endpoint_leaf  = str()
    endpoint_staticport = list()
    endpoint_desc = str()
    endpoint_ip = str()
    endpoint_encapvlan = str()

    path_csv = getCSVPath('out_files', 'endpoint.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file)
        csv_writter.writerow(
            ['tenant', 'ap', 'epg', 'mac', 'ip', 'encap-vlan', 'leaf', 'static_port', 'description'])
        
        # generating data from json
        endpoint_list = json.loads(response.text)
        endpoint = endpoint_list['imdata']
        #print(endpoint)
        for i in endpoint:
            for j in i:
                endpoint_encapvlan = i[j]['attributes']['encap']
                endpoint_mac = i[j]['attributes']['mac']
                if 'children' in i[j]:
                    for_k = i[j]['children']
                    for k in for_k:
                        for l in k:
                            if 'fvIp' in l:
                                endpoint_ip = k[l]['attributes']['addr']
                for_k = i[j]['children']
                # loop children of fvCEp
                for k in for_k:
                    for l in k:
                        if 'fvRsCEpToPathEp' in l:
                            # workaround for api query sub class fvRsCEpToPathEp not returning dn
                            endpoint_data_temp = i[j]['attributes']['dn'] + '/' + k[l]['attributes']['rn']
                            endpoint_data = endpoint_data_temp.split('/')
                            # for endpoint listed as vrf endpoint
                            if 'ctx-' in endpoint_data_temp:
                                #print(endpoint_data)
                                endpoint_tenant = endpoint_data[1].replace('tn-','')
                                endpoint_ap = ''
                                endpoint_epg = endpoint_data[2].replace('ctx-','')
                                ep_leaf = ['protpaths-','paths-']
                                endpoint_leaf  = re.sub('|'.join(sorted(ep_leaf, key = len, reverse = True)), '', endpoint_data[6])
                                ep_staticport = ['pathep-',r'\[','\]']
                                endpoint_desc='vrf endpoint'
                                if len(endpoint_data) == 8:
                                    endpoint_staticport.append(re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[7]))
                                else:
                                    temp_endpoint_staticport = re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[7]) + '/' 
                                    temp_endpoint_staticport += re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[8])
                                    endpoint_staticport.append(temp_endpoint_staticport)                                    
                            # for endpoint category vmm
                            else:
                                #print(endpoint_data)
                                endpoint_tenant = endpoint_data[1].replace('tn-','')
                                endpoint_ap = endpoint_data[2].replace('ap-','')
                                endpoint_epg = endpoint_data[3].replace('epg-','')
                                ep_staticport = ['pathep-','pathgrp-',r'\[','\]']
                                # assign vmm attached leaf node
                                if 'pathgrp-' in endpoint_data_temp:
                                    leaf_len = len(k[l]['children'][0:])
                                    leaf_count = 0
                                    for leaf in k[l]['children'][0:]:
                                        if leaf_count ==0:
                                            endpoint_leaf  = leaf['fvReportingNode']['attributes']['id']
                                        else:
                                            endpoint_leaf  += '-' + leaf['fvReportingNode']['attributes']['id']
                                        leaf_count += 1
                                        if leaf_count == leaf_len:
                                            break
                                    endpoint_desc='vmm endpoint vcenter'       
                                    endpoint_staticport.append(re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[7]))
                                # assign leaf node to non vmm
                                else:
                                    ep_leaf = ['protpaths-','paths-']
                                    endpoint_leaf  = re.sub('|'.join(sorted(ep_leaf, key = len, reverse = True)), '', endpoint_data[7])
                                    endpoint_desc=''
                                    if len(endpoint_data) == 9:
                                        endpoint_staticport.append(re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[8]))
                                    else:
                                        temp_endpoint_staticport = re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[8]) + '/'
                                        temp_endpoint_staticport += re.sub('|'.join(sorted(ep_staticport, key = len, reverse = True)), '', endpoint_data[9])
                                        endpoint_staticport.append(temp_endpoint_staticport) 
                endpoint_staticport_string = ' '.join(endpoint_staticport)
                # for endpoint without fvRsCEpToPathEp (e.g vrf (ctx-x))
                if endpoint_tenant == '' and endpoint_ap == '' and endpoint_epg == '':
                    endpoint_tenant = endpoint_data[1].replace('tn-','')
                    endpoint_ap = ''
                    endpoint_epg = endpoint_data[2].replace('ctx-','')
                    endpoint_leaf = ''
                    endpoint_desc='vrf endpoint'

                csv_writter.writerow([endpoint_tenant, endpoint_ap,endpoint_epg,endpoint_mac,endpoint_ip,endpoint_encapvlan, endpoint_leaf,endpoint_staticport_string,endpoint_desc])
                endpoint_tenant = ''
                endpoint_ap = ''
                endpoint_epg = ''
                endpoint_mac = ''
                endpoint_leaf = ''
                endpoint_desc = ''
                endpoint_ip = ''
                endpoint_encapvlan = ''
                endpoint_staticport.clear()   

# moquery -c cdpAdjEp -o json & moquery -c lldpAdjEp -o json
def parsingCdpLldpToCsv(param_apic_url:str, param_cookie:dict):
    # query the apic
    response_cdp = apic_query(apic=param_apic_url, path='/api/node/class/cdpAdjEp.json', cookie=param_cookie)
    response_lldp = apic_query(apic=param_apic_url, path='/api/node/class/lldpAdjEp.json', cookie=param_cookie)

    # variable definition
    lldp = dict()
    cdp = dict()
    protocol = str()
    pod = str()
    local_device = str()
    local_port = str()
    remote_device = str()
    remote_port = str()

    path_csv = getCSVPath('out_files', 'cdp_lldp.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file)
        # write header to csv
        csv_writter.writerow(['protocol','pod','local_device','local_port','remote_device','remote_port'])
        
        # loop cdp 
        cdp_list = json.loads(response_cdp.text)
        cdp = cdp_list['imdata']
        for i in cdp:
            for j in i:
                protocol = 'cdp'
                pod = i[j]['attributes']['dn'].split('/')[1]
                local_device = i[j]['attributes']['dn'].split('/')[2].replace('node-','')
                local_port_remove = ['if-\[','\]']
                local_port_temp = i[j]['attributes']['dn'].split('/')[6] + '/' + i[j]['attributes']['dn'].split('/')[7]
                local_port= re.sub('|'.join(sorted(local_port_remove, key = len, reverse = True)), '', local_port_temp)
                remote_device = i[j]['attributes']['devId']
                remote_port = i[j]['attributes']['portId']
                csv_writter.writerow([protocol,pod,local_device,local_port,remote_device,remote_port])

        # loop lldp
        lldp_list = json.loads(response_lldp.text)
        lldp = lldp_list['imdata']
        for i in lldp:
            for j in i:
                protocol = 'lldp'
                pod = i[j]['attributes']['dn'].split('/')[1]
                local_device = i[j]['attributes']['dn'].split('/')[2].replace('node-','')
                local_port_remove = ['if-\[','\]']
                local_port_temp = i[j]['attributes']['dn'].split('/')[6] + '/' + i[j]['attributes']['dn'].split('/')[7]
                local_port= re.sub('|'.join(sorted(local_port_remove, key = len, reverse = True)), '', local_port_temp)
                remote_device = i[j]['attributes']['sysName']
                remote_port = i[j]['attributes']['portIdV']
                csv_writter.writerow([protocol,pod,local_device,local_port,remote_device,remote_port])

# moquery -c fvAEPg -x 'rsp-subtree=full' -o json
def parsingEpgToCsv(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/fvAEPg.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    epg = dict()
    epg_tenant = str()
    epg_app = str()
    epg_name = str()
    epg_domain = list()
    epg_bd = str()
    epg_contract = dict(provider=list(),consumer=list())
    epg_port = list()
    epg_subnet = list()

    path_csv = getCSVPath('out_files', 'epg.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file)
        # write header to csv
        csv_writter.writerow(['tenant','app','epg','bridge_domain','domain','contract','subnet','static_port'])
        
        # generating data from json
        epg_list = json.loads(response.text)
        epg = epg_list['imdata']        
        for i in epg:
            for j in i:
                epg_tenant = i[j]['attributes']['dn'].split('/')[1]
                epg_app = i[j]['attributes']['dn'].split('/')[2]
                epg_name = i[j]['attributes']['name']
                for_k = i[j]['children']
                # loop childer of fvAEPg
                for k in for_k:
                    for l in k:
                        if 'fvRsProv' in l:
                            provider_cont = k[l]['attributes']['tDn'].split('/')[-1]
                            epg_contract['provider'].append('[' + provider_cont + ']')
                        if 'fvRsCons' in l:
                            consumer_cont = k[l]['attributes']['tDn'].split('/')[-1]
                            epg_contract['consumer'].append('[' + consumer_cont + ']')
                        if 'fvRsBd' in l:
                            epg_bd = k[l]['attributes']['tnFvBDName']
                        if 'fvRsDomAtt' in l:
                            epg_domain.append(k[l]['attributes']['tDn'].split('/')[-1])
                        #tambah data static port
                        if 'fvRsPathAtt' in l:
                            data_path = k[l]['attributes']['tDn'].split('/')[3]
                            data_leaf = k[l]['attributes']['tDn'].split('/')[2]
                            remove_leaf = ['protpaths-','paths-']
                            remove_path = ['pathep-\[','\]']
                            if 'eth' in data_path:
                                data_path = k[l]['attributes']['tDn'].split('/')[3] + '/' + k[l]['attributes']['tDn'].split('/')[-1]
                                static_path = \
                                    re.sub('|'.join(sorted(remove_leaf, key = len, reverse = True)), '', data_leaf) \
                                    + '-' + \
                                    re.sub('|'.join(sorted(remove_path, key = len, reverse = True)), '', data_path)                                    
                            else:
                                static_path = re.sub('|'.join(sorted(remove_path, key = len, reverse = True)), '', data_path)
                            epg_port.append(static_path)
                        if 'fvSubnet' in l:
                            data_subnet = k[l]['attributes']['ip']
                            epg_subnet.append(data_subnet)
                # grouping domain
                phys_domain = list()
                vmm_domain = list()
                for dom in epg_domain:
                    if 'phys-' in dom:
                        phys_domain_temp = str(dom).replace('phys-','')
                        phys_domain.append('[' + phys_domain_temp + ']')
                    if 'dom-' in dom:
                        vmm_domain_temp = str(dom).replace('dom-','')
                        vmm_domain.append('[' + vmm_domain_temp + ']')
                domain = 'Phsycal dom: ' + ' '.join(phys_domain) + ' | VMM dom: ' + ' '.join(vmm_domain)
                # strip brc-
                contract_provider = ' '.join(epg_contract['provider'])
                contract_consumer = ' '.join(epg_contract['consumer'])
                contract = 'Provider: ' + contract_provider.replace('brc-','') + ' | Consumer: ' + contract_consumer.replace('brc-','')
                # write data to csv
                static_port = ' '.join(epg_port)
                epg_sub = ' '.join(epg_subnet)
                csv_writter.writerow([epg_tenant.replace('tn-',''),epg_app.replace('ap-',''),epg_name,epg_bd,domain,contract,epg_sub,static_port])
                # clearing list 
                epg_contract['provider'].clear()
                epg_contract['consumer'].clear()
                epg_domain.clear()
                epg_port.clear()
                epg_subnet.clear()

# moquery -c l1PhysIf -x 'rsp-subtree=full' -o json
def parsingIntoCsv(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/l1PhysIf.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    interface = dict()
    int_id = str()
    int_pod = str()
    int_node = str()
    int_speed = str()
    int_adminst = str()
    int_operst = str()
    int_duplex = str()
    int_remark = str()

    path_csv = getCSVPath('out_files', 'int.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file)
        csv_writter.writerow(['pod','node','interface','speed','admins-state','oper-state','duplex','remark'])
        
        # generating data from json
        int_list = json.loads(response.text)
        interface = int_list['imdata']        
        for i in interface:
            for j in i:
                int_pod = i[j]['attributes']['dn'].split('/')[1]
                int_node = i[j]['attributes']['dn'].split('/')[2].replace('node-','')
                int_id = i[j]['attributes']['id']
                int_adminst = i[j]['attributes']['adminSt']
                for_k = i[j]['children']
                # loop children of l1PhysIf
                for k in for_k:
                    for l in k:
                        if 'ethpmPhysIf' in l:
                            int_operst = k[l]['attributes']['operSt']
                            int_duplex = k[l]['attributes']['operDuplex']
                            int_remark = k[l]['attributes']['operStQual']
                            int_speed = k[l]['attributes']['operSpeed']
                csv_writter.writerow([int_pod,int_node,int_id,int_speed,int_adminst,int_operst,int_duplex,int_remark])

# moquery -c pcAggrIf -x 'rsp-subtree=full' -o json
def parsingPcVpcToCsv(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/pcAggrIf.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    pc_vpc = dict()
    vpc_domain = str()
    vpc_id = str()
    port_channel = str()
    polgroup_name = str()
    lacp_mode = str()
    status = str()
    active_vlan = str()
    leaf_id = str()
    member = list()
    description = str()

    path_csv = getCSVPath('out_files', 'pc_vpc.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file)
        csv_writter.writerow(
            ['vpc_domain', 'vpc_id', 'port_channel', 'polgroup_name', 'lacp_mode', 'status', 'active_vlan', 'leaf_id', 'member','description']
        )

        # generating data from json
        pc_vpc_list = json.loads(response.text)
        pc_vpc = pc_vpc_list['imdata']        
        for i in pc_vpc:
            for j in i:
                polgroup_name = i[j]['attributes']['name']
                leaf_id = i[j]['attributes']['dn'].split('/')[2].replace('node-','')
                port_channel = i[j]['attributes']['id']
                lacp_mode = i[j]['attributes']['operChannelMode']
                for_k = i[j]['children']
                # loop children of pcAggrIf
                for k in for_k:
                    for l in k:
                        if 'ethpmAggrIf' in k:
                            active_vlan = '[' + k[l]['attributes']['allowedVlans'].replace(',',':') + ']'
                            status  = k[l]['attributes']['operSt']
                            members = k[l]['attributes']['activeMbrs'].split(',')
                            for mem in members:
                                if 'eth' in mem:
                                    member.append(mem)
                        if 'pcRtVpcConf' in k:
                            vpc_domain = k[l]['attributes']['tDn'].split('/')[6].replace('dom-','')
                            vpc_id = k[l]['attributes']['tSKey']
                        if not vpc_domain:
                            description = 'Port-channel'
                        else:
                            description = ''
                csv_writter.writerow(
                    [
                        vpc_domain,
                        vpc_id,
                        port_channel,
                        polgroup_name,
                        lacp_mode,
                        status,
                        active_vlan,
                        leaf_id,
                        '[' + ':'.join(member) + ']',
                        description                        
                    ]
                )
                vpc_domain = ''
                vpc_id = ''
                member.clear()

# moquery -c l2extOut -x 'rsp-subtree=full' -o json
def parsingL2outToCsv(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/l2extOut.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    l2out = dict()
    tenant = str()
    bd = str()
    l2out_name = str()
    vlan = str()
    domain  = str()
    leaf = list()
    l2out_path = list()
    contract = dict(provider=list(),consumer=list())

    path_csv = getCSVPath('out_files', 'l2out.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file)
        csv_writter.writerow(
            ['tenant', 'bd', 'l2out', 'vlan', 'domain', 'leaf', 'path', 'contract']
        )

        # generating data from json
        l2out_list = json.loads(response.text)
        l2out = l2out_list['imdata']
        for i in l2out:
            for j in i:
                tenant = i[j]['attributes']['dn'].split('/')[1].replace('tn-','')
                l2out_name = i[j]['attributes']['name']
                for_k = i[j]['children']
                # loop childer of l2extOut
                for k in for_k:
                    for l in k:
                        if 'l2extRsL2DomAtt' in l:
                            domain = k[l]['attributes']['tDn'].split('/')[1].replace('l2dom-','')
                        if 'l2extRsEBd' in l:
                            bd = k[l]['attributes']['tnFvBDName']
                            vlan = k[l]['attributes']['encap']
                        if 'l2extLNodeP' in l:
                            if 'children' in k[l]:
                                for_m = k[l]['children']
                                for m in for_m:
                                    for n in m:
                                        if 'l2extLIfP' in n:
                                               if 'children' in m[n]:
                                                for_o = m[n]['children']
                                                for o in for_o:
                                                    for p in o:
                                                        if 'l2extRsPathL2OutAtt' in p:
                                                            dn_len = o[p]['attributes']['dn'].split('/')
                                                            if len(dn_len) == 9:
                                                                leaf_prefix = ['protpaths-','paths-']
                                                                leaf_temp = o[p]['attributes']['dn'].split('/')[7]
                                                                leaf.append(re.sub('|'.join(sorted(leaf_prefix, key = len, reverse = True)), '', leaf_temp))
                                                                leaf_path = re.sub('|'.join(sorted(leaf_prefix, key = len, reverse = True)), '', leaf_temp)
                                                                path_prefix = ['pathep-\[','\]']
                                                                path_temp =  o[p]['attributes']['dn'].split('/')[-1]
                                                                l2out_path.append(leaf_path + ': ' + re.sub('|'.join(sorted(path_prefix, key = len, reverse = True)), '', path_temp)) 
                                                                '''print(leaf)
                                                                print(l2out_path)'''
                                                            else:
                                                                leaf_prefix = ['protpaths-','paths-']
                                                                leaf_temp = o[p]['attributes']['dn'].split('/')[7]
                                                                leaf.append(re.sub('|'.join(sorted(leaf_prefix, key = len, reverse = True)), '', leaf_temp))
                                                                leaf_path = re.sub('|'.join(sorted(leaf_prefix, key = len, reverse = True)), '', leaf_temp)
                                                                path_prefix = ['pathep-\[','\]']
                                                                path_temp =  o[p]['attributes']['dn'].split('/')[8] + '/' + o[p]['attributes']['dn'].split('/')[-1]
                                                                l2out_path.append(leaf_path + ': ' + re.sub('|'.join(sorted(path_prefix, key = len, reverse = True)), '', path_temp))
                        if 'l2extInstP' in l:
                            if 'children' in k[l]:
                                for_m = k[l]['children']
                                for m in for_m:
                                    for n in m:
                                        if 'fvRsCons' in n:
                                            consumer_cont = m[n]['attributes']['tDn'].split('/')[-1]
                                            contract['consumer'].append(consumer_cont)
                                        if 'fvRsCons' in n:
                                            provider_cont = m[n]['attributes']['tDn'].split('/')[-1]
                                            contract['consumer'].append(provider_cont)  
                leaf = list(dict.fromkeys(leaf)) 
                csv_writter.writerow(
                    [
                        tenant,
                        bd,
                        l2out_name,
                        vlan,
                        domain,
                        '[' +  ' '.join(leaf) + ']',
                        '[' + ' '.join(l2out_path) + ']',
                        'Provider: ' + ' '.join(contract['provider']) + ' | Consumer: ' + ' '.join(contract['consumer'])
                    ]
                )                            
                contract['consumer'].clear()
                contract['provider'].clear()   
                l2out_path.clear()
                leaf.clear() 

# moquery -c l3extOut -x 'rsp-subtree=full' -o json                                        
def parsingL3outToCsv3(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/l3extOut.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    l3out = dict()
    l3out_ls = list()
    l3out_ls_data = dict(name=str(),tenant=str(),node=list(),subnet=list())
    logical_node_profile = list()
    logical_node_profile_data = dict(name=str(),interface=list(),leaf=list())
    logical_interface = list()
    logical_interface_data = dict(name=str(),path=list(),vlan=str(),ip_address=list(),l3out_type = str())

    path_csv = getCSVPath('out_files', 'l3out.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file, delimiter=";")
        csv_writter.writerow(
            ['tenant', 'l3out_name', 'logical_node_profile', 'leaf', 'logical_interface', 'path', 'ext-subnet', 'ip_address','vlan','l3out_type']
        )
        # compile data   
        # looping l3out 
        # generating data from json
        l3out_list = json.loads(response.text)
        l3out = l3out_list['imdata']
        for i in l3out:         
            for j in i:
                l3out_ls_data['tenant'] = i[j]['attributes']['dn'].split('/')[1].replace('tn-','')
                l3out_ls_data['name'] = i[j]['attributes']['name']                            
                for_k = i[j]['children']                
                # looping logical node
                for k in for_k:                    
                    for l in k:
                        if 'l3extInstP' in l:
                            if 'children' in k[l]:
                                for_m = k[l]['children']
                                for m in for_m:
                                    for n in m:
                                        if 'l3extSubnet' in n:
                                            subnet = m[n]['attributes']['ip'] + ' scope: ' + m[n]['attributes']['scope']
                                            l3out_ls_data['subnet'].append(subnet)
                        if 'l3extLNodeP' in l:
                            temp_logical_interface_data = dict(name=str(),path=list(),vlan=str(),ip_address=list(),l3out_type = str())
                            logical_node_profile_data['name'] = k[l]['attributes']['name']
                            l3extLNodeP_dn = i[j]['attributes']['dn'] + '/' + k[l]['attributes']['rn']
                            if 'children' in k[l]:
                                for_m = k[l]['children']
                                # looping interface
                                for m in for_m:
                                    for n in m:
                                        if 'l3extLIfP' in n:  
                                            logical_interface_data['name'] = m[n]['attributes']['name'] 
                                            l3extLIfP_dn = l3extLNodeP_dn + '/' + m[n]['attributes']['rn']
                                            if 'children' in m[n]:
                                                for_o = m[n]['children']
                                                # looping data interface
                                                for o in for_o:
                                                    for p in o:
                                                        if 'l3extRsPathL3OutAtt' in p: 
                                                            logical_interface_data['l3out_type'] = o[p]['attributes']['ifInstT']
                                                            logical_interface_data['vlan'] = o[p]['attributes']['encap'].replace('vlan-','')
                                                            l3extRsPathL3OutAtt_dn = l3extLIfP_dn + '/' + o[p]['attributes']['rn']
                                                            path_len = l3extRsPathL3OutAtt_dn.split('/')
                                                            
                                                            if len(path_len) == 9:
                                                                path_prefix = ['pathep-\[','\]']
                                                                leaf_id = l3extRsPathL3OutAtt_dn.split('/')[7].replace('protpaths-','')
                                                                path_temp = leaf_id + ': ' + l3extRsPathL3OutAtt_dn.split('/')[8]
                                                                logical_interface_data['path'].append(re.sub('|'.join(sorted(path_prefix, key = len, reverse = True)), '', path_temp))
                                                            else:
                                                                path_prefix = ['pathep-\[','\]']
                                                                leaf_id = l3extRsPathL3OutAtt_dn.split('/')[7].replace('paths-','')
                                                                path_temp = \
                                                                    leaf_id \
                                                                    + ': ' + \
                                                                    l3extRsPathL3OutAtt_dn.split('/')[8] \
                                                                    + '/' + \
                                                                    l3extRsPathL3OutAtt_dn.split('/')[9]
                                                                logical_interface_data['path'].append(re.sub('|'.join(sorted(path_prefix, key = len, reverse = True)), '', path_temp))
                                                            if 'sub-interface' in logical_interface_data['l3out_type'] or 'l3-port' in logical_interface_data['l3out_type']:
                                                                logical_interface_data['ip_address']
                                                                logical_interface_data['ip_address'].append(o[p]['attributes']['addr'])
                                                            else:
                                                                if 'children' in o[p]:
                                                                    for_q = o[p]['children']
                                                                    for r in for_q:
                                                                        for s in r:
                                                                            if 'l3extMember' in s:
                                                                                logical_interface_data['ip_address'].append('side ' + r[s]['attributes']['side'] + ': ' + r[s]['attributes']['addr']) 
                                                                                if 'children' in r[s]:
                                                                                    ip_address_virtual = r[s]['children']
                                                                                    logical_interface_data['ip_address'].append('virtual: ' +  ip_address_virtual[0]['l3extIp']['attributes']['addr'])
                                                                            if 'l3extIp' in s:
                                                                                  logical_interface_data['ip_address'].append(o[p]['attributes']['addr'])
                                                                else:
                                                                    logical_interface_data['ip_address'].append(o[p]['attributes']['addr'])
                                            
                                            temp_logical_interface_data['name'] = logical_interface_data['name']
                                            temp_logical_interface_data['vlan']  = logical_interface_data['vlan'] 
                                            temp_logical_interface_data['l3out_type']  = logical_interface_data['l3out_type']
                                            temp_logical_interface_data['ip_address']  = logical_interface_data['ip_address'].copy()
                                            temp_logical_interface_data['path']  = logical_interface_data['path'].copy()
                                            logical_interface.append(temp_logical_interface_data.copy())  
                                            logical_interface_data['name'] = ''
                                            logical_interface_data['vlan'] = ''
                                            logical_interface_data['l3out_type'] = ''  
                                            logical_interface_data['ip_address'].clear()
                                            logical_interface_data['path'].clear()   
                                        if 'l3extRsNodeL3OutAtt' in n:
                                            data_leaf = m[n]['attributes']['tDn'].split('/')[2].replace('node-','')
                                            logical_node_profile_data['leaf'].append(data_leaf)
                            if len(logical_interface) != 0:
                                logical_node_profile_data['interface'].append(logical_interface.copy())
                            temp_logical_interface_data = dict(name=str(),path=list(),vlan=str(),ip_address=list(),l3out_type = str())
                            logical_interface.clear()
                logical_node_profile.append(logical_node_profile_data.copy())
                logical_node_profile_data.clear()
                logical_node_profile_data = dict(name=str(),interface=list(),leaf=list())
            l3out_ls_data['node'].append(logical_node_profile.copy())
            logical_node_profile.clear() 
            temp_l3out_ls_data = dict(name=str(),tenant=str(),node=list(),subnet=list())
            temp_l3out_ls_data = l3out_ls_data.copy()
            l3out_ls.append(temp_l3out_ls_data.copy())                       
            l3out_ls_data.clear()
            l3out_ls_data = dict(name=str(),tenant=str(),node=list(),subnet=list())

        # delete below
        # print('tenant;l3out_name;logical_node_profile;leaf;logical_interface;path;vlan;ip_address;l3out_type;ext-subnet')
        for i in l3out_ls:
            tenant = i['tenant']
            l3out_name = i['name']
            ext_subnet = ','.join(i['subnet'])
            #print(i)
            for j in i['node']:
                for k in j:
                    #print(k)
                    node = k['name']
                    leaf = ','.join(k['leaf'])
                    if len(k['interface']) == 0:
                        csv_writter.writerow(
                            [
                                tenant,
                                l3out_name,
                                node,
                                leaf,
                                ext_subnet
                            ]
                        )
                    for l in k['interface']:
                        for m in l:
                            #print(m)
                            interface = m['name']
                            ip_address = list(dict.fromkeys(m['ip_address']))
                            ip_addr_res = ','.join(ip_address)                            
                            path = ','.join(m['path'])
                            vlan = m['vlan']
                            l3_type = m['l3out_type']
                            csv_writter.writerow(
                                [
                                    tenant,
                                    l3out_name,
                                    node,
                                    leaf,
                                    interface,
                                    path,
                                    ext_subnet,
                                    ip_addr_res,
                                    vlan,
                                    l3_type
                                ]
                            )            

# moquery -c infraAttEntityP -x 'rsp-subtree=full' -o json
def domToAepCSV(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/infraAttEntityP.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    aep = dict()
    aep_name = str()
    aep_dom = str()
    dom_type = str()

    path_csv = getCSVPath('out_files', 'dom_to_aep.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file)
        csv_writter.writerow(
            ['domain_type', 'domain', 'aep']
        )

        # generating data from json
        aep_list = json.loads(response.text)
        aep = aep_list['imdata']
        for i in aep:
            for j in i:
                aep_name = i[j]['attributes']['name']
                #loop children for domain
                for_k = i[j]['children']
                for k in for_k:
                    for l in k:
                        if 'infraRsDomP' in k:
                            data = k[l]['attributes']['tDn']
                            data_prefix = ['uni\/l3dom-','uni\/l2dom-','uni\/phys-','uni\/vmmp-VMware\/dom-']
                            aep_dom = re.sub('|'.join(sorted(data_prefix, key = len, reverse = True)), '', data)
                            dom_type = data.split('-')[0].replace('uni/','')
                            csv_writter.writerow(
                                [
                                    dom_type,
                                    aep_dom,
                                    aep_name
                                ]
                            )

# moquery -c infraAttEntityP -x 'rsp-subtree=full' -o json
def polgroupToAepCSV(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/infraAttEntityP.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    aep = dict()
    aep_name = str()
    aep_polgroup = str()

    path_csv = getCSVPath('out_files', 'polgroup_to_aep.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file)
        csv_writter.writerow(
            ['polgroup', 'aep']
        )

        # generating data from json
        aep_list = json.loads(response.text)
        aep = aep_list['imdata']
        for i in aep:
            for j in i:
                aep_name = i[j]['attributes']['name']
                #loop children for polgroup
                for_k = i[j]['children']
                for k in for_k:
                    for l in k:
                        if 'infraRtAttEntP' in k:
                            data = k[l]['attributes']['tDn'].split('/')[3]
                            data_prefix = ['accbundle-','accportgrp-']
                            aep_polgroup = re.sub('|'.join(sorted(data_prefix, key = len, reverse = True)), '', data)
                            csv_writter.writerow(
                                [
                                    aep_polgroup,
                                    aep_name
                                ]
                            )

# moquery -c infraHPortS -x 'rsp-subtree=full' -o json
# mapping single interface ke polgroup
def intToPolgroupCSV(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = apic_query(apic=param_apic_url, path='/api/node/class/infraHPortS.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    interface = dict()
    intsel = str()
    intpol = str()
    
    path_csv = getCSVPath('out_files', 'int_to_polgroup.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file)
        csv_writter.writerow(
            ['intsel', 'intpol']
        )

        # generating data from json
        int_list = json.loads(response.text)
        interface = int_list['imdata']
        for i in interface:
            for j in i:
                leaf = i[j]['attributes']['dn'].split('/')[2].replace('accportprof-','')
                #remove_prefix = ['hports-','-typ-range']
                #temp = i[j]['attributes']['rn']
                #leaf_interface = re.sub('|'.join(sorted(remove_prefix, key = len, reverse = True)), '', temp)
                leaf_interface = i[j]['attributes']['name']
                intsel = leaf + '-eth1/' + leaf_interface
                #loop children
                for_k = i[j]['children']            
                for k in for_k:
                    len_k = len(k)
                    counter = 0
                    for l in k:
                        if 'infraRsAccBaseGrp' in k:
                            data = k[l]['attributes']['tDn'].split('/')[3]
                            intpol_prefix = ['accbundle-','accportgrp-']
                            intpol = re.sub('|'.join(sorted(intpol_prefix, key = len, reverse = True)), '', data)
                            csv_writter.writerow(
                                [
                                    intsel,
                                    intpol
                                ]
                            )
