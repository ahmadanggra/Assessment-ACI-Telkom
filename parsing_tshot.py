import json
import requests
import re
import os
import csv
import parsing

# moquery -c fvCEp -x 'rsp-subtree=full'  -o json
def parsingEpToCsv_ep_rouge(param_apic_url:str, param_cookie:dict):
    # query the apic
    response = parsing.apic_query(apic=param_apic_url, path='/api/node/class/fvCEp.json?rsp-subtree=full', cookie=param_cookie)

    # variable definition
    endpoint = dict()
    endpoint_tenant = str()
    endpoint_ap = str()
    endpoint_epg = str()
    endpoint_bd = str()
    endpoint_mac = str()
    endpoint_ip = str()

    path_csv = parsing.getCSVPath('out_files', 'ep_rouge.csv')
    with open(path_csv, 'w', newline='', encoding='utf-8') as file:
        csv_writter = csv.writer(file)
        csv_writter.writerow(
            ['tenant', 'ap', 'epg', 'bd', 'ip', 'mac'])
        
        # generating data from json
        endpoint_list = json.loads(response.text)
        endpoint = endpoint_list['imdata']
        #print(endpoint)
        for i in endpoint:
           for j in i:
                endpoint_dn = i[j]['attributes']['dn'].split('/')
                endpoint_bdn = i[j]['attributes']['bdDn'].split('/')
                endpoint_tenant = endpoint_dn[1].replace('tn-','')
                endpoint_ap = endpoint_dn[2].replace('ap-','')
                endpoint_epg = endpoint_dn[3].replace('epg-','')
                if endpoint_bdn != '':
                    endpoint_bd = endpoint_bdn[-1].replace('BD-','')
                # loop children of fvCEp for children fvIp, because fvCEp['attributes']['ip'] no longer valid on APIC 5.x
                #endpoint_ip = i[j]['children']['fvIp']['attributes']['addr']
                if 'children' in i[j]:
                    for_k = i[j]['children']
                    for k in for_k:
                        for l in k:
                            if 'fvIp' in l:
                                endpoint_ip = k[l]['attributes']['addr']
                endpoint_mac =  i[j]['attributes']['mac']
                #print(endpoint_tenant + ', ' + endpoint_ap + ', ' + endpoint_epg + ', ' + endpoint_bd + ', ' + endpoint_ip + ', ' + endpoint_mac)
                #not write down if ap listed as ctx (vrf)
                if 'ctx-' not in endpoint_dn[2]:
                    csv_writter.writerow([endpoint_tenant, endpoint_ap, endpoint_epg, endpoint_bd, endpoint_ip, endpoint_mac])
                endpoint_tenant = ''
                endpoint_ap = ''
                endpoint_epg = ''
                endpoint_bd = ''
                endpoint_mac = ''
                endpoint_ip = '' 