#!/usr/bin/env python

"""
HyperFlex Clean-Up (Reset) Script
Author: Michael Zimmerman
Contributors: Matthew Garrett
Email: mzcisco01@gmail.com

Copyright (c) 2018 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.0 (the "License"). You may obtain a copy of the
License at:

             https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

##################
# Packages #######
##################

import os
import os.path
from os import path
import sys
import time
import pexpect
import getpass
from threading import Thread
import json
from colorama import Fore, Back, Style
from IPy import IP

from pyVim import connect
from pyVmomi import vim

import intersight_rest as intersight_handle



##################
# FUNCTIONS ######
##################

def ucs_connect(ucsm_ip, ucsm_user, ucsm_pass):
    ucs_handle = UcsHandle(ucsm_ip, ucsm_user, ucsm_pass)
    ucs_handle.login()
    return ucs_handle


def org_exists(ucs_handle, org_name):
    filter_str = "(name, \""+org_name+"\")"
    object = ucs_handle.query_classid(class_id="orgOrg", filter_str=filter_str)
    if object:
        return True
    else:
        return False


def vmedia_policy_exists(ucs_handle, vmedia_policy_name):
    filter_str = "(name, \""+vmedia_policy_name+"\")"
    object = ucs_handle.query_classid(class_id="cimcvmediaMountConfigPolicy", filter_str=filter_str)
    if object:
        return True
    else:
        return False


def get_sps_in_org(ucs_handle, org_name):
    objects = ucs_handle.query_children(in_dn="org-root/org-"+org_name,class_id="lsServer",filter_str="(type,\"instance\",type=\"eq\")")
    return objects


def get_sp_template_dn(ucs_handle, sp_object):
    sp_template_dn = sp_object.oper_src_templ_name
    return sp_template_dn


def get_sp_template_boot_policy_dn(ucs_handle, sp_template_object):
    sp_template_boot_policy_object = sp_template_object.oper_boot_policy_name
    return sp_template_boot_policy_object


def get_sp_template_vmedia_policy_dn(ucs_handle, sp_template_object):
    sp_template_vmedia_policy_dn = sp_template_object.oper_vmedia_policy_name
    return sp_template_vmedia_policy_dn


def get_ucs_object_by_dn(ucs_handle, dn):
    object = ucs_handle.query_dn(dn)
    return object


def set_sp_template_vmedia_policy(ucs_handle, sp_template_object, new_vmedia_policy_dn):
    sp_template_object.vmedia_policy_name = vmedia_policy_name
    ucs_handle.set_mo(sp_template_object)
    ucs_handle.commit()
    sp_template_object = get_ucs_object_by_dn(ucs_handle, sp_template_object.dn)
    return sp_template_object


def set_vmedia_boot_policy(ucs_handle, sp_template_boot_policy_object, org_name):
    sp_template_boot_policy_name = sp_template_boot_policy_object.name
    mo = LsbootPolicy(parent_mo_or_dn="org-root/org-"+org_name, name=sp_template_boot_policy_name)
    LsbootVirtualMedia(parent_mo_or_dn=mo, access="read-only-remote-cimc", lun_id="0", order="3")
    ucs_handle.add_mo(mo, True)
    ucs_handle.commit()

    if sp_template_boot_policy_name == "HyperFlex":
        mo = LsbootUsbFlashStorageImage(parent_mo_or_dn="org-root/org-hxcluster/boot-policy-HyperFlex/storage/local-storage", order="3")
    elif sp_template_boot_policy_name == "HyperFlex-m5":
        mo = LsbootEmbeddedLocalDiskImage(parent_mo_or_dn="org-root/org-"+org_name+"/boot-policy-"+sp_template_boot_policy_name+"/storage/local-storage", order="3")
    ucs_handle.add_mo(mo, True)
    mo = LsbootVirtualMedia(parent_mo_or_dn="org-root/org-"+org_name+"/boot-policy-"+sp_template_boot_policy_name, access="read-only-remote-cimc", order="1")
    ucs_handle.add_mo(mo, True)
    mo = LsbootVirtualMedia(parent_mo_or_dn="org-root/org-"+org_name+"/boot-policy-"+sp_template_boot_policy_name, access="read-only", order="2")
    ucs_handle.add_mo(mo, True)
    ucs_handle.commit()


def sp_power_action(ucs_handle, sp_dn, action):
    mo = LsPower(parent_mo_or_dn=sp_dn, state=action)
    ucs_handle.add_mo(mo, True)
    ucs_handle.commit()


def get_sp_kvm_ips(ucs_handle, sp_objects):
    sp_kvm_ips = {}
    for sp_object in sp_objects:
        kvm_ip = ucs_handle.query_children(in_dn=sp_object.dn,class_id="vnicIpV4PooledAddr")[0].addr
        sp_kvm_ips.update( {sp_object.name:kvm_ip} )
    return sp_kvm_ips


def monitor_esxi_prompt(sp_name, sp_kvm_ip):
    ssh_newkey = "Are you sure you want to continue connecting"
    cmd = "ssh -l %s %s -oKexAlgorithms=diffie-hellman-group1-sha1,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" % (ucsm_user, sp_kvm_ip)
    kvm_session = pexpect.spawn(cmd, timeout=60)
    kvm_session.timeout=600
    i = kvm_session.expect([ssh_newkey, '[Pp]assword:'])
    if i == 0:
        kvm_session.sendline("yes")
        kvm_session.expect("[Pp]assword:")
    time.sleep(5)
    kvm_session.sendline(ucsm_pass)
    kvm_session.expect("Connection to Exit|Exit the session")
    kvm_session.sendcontrol('d')
    time.sleep(2)
    kvm_session.expect("login:")
    kvm_session.sendline("root")
    kvm_session.expect("[Pp]assword:")
    kvm_session.sendline("Cisco123")
    kvm_session.expect(":~]")
    print ("   <> Successfully connected to ESXi CLI prompt on service profile: "+sp_name)


def get_phys_server_dns(ucs_handle, sp_objects):
    phy_server_dns = []
    for object in sp_objects:
        phy_server_dns.append(object.pn_dn)
    return phy_server_dns


def monitor_phy_server_assoc(ucs_handle, phy_server_dn):
    timeout = 1800
    timepassed = 0
    while True:
        object = get_ucs_object_by_dn(ucs_handle, phy_server_dn)
        association = object.association
        availability = object.availability
        if association == "none" and availability == "available":
            print ("   <> Physical server: "+phy_server_dn+" successfully dissassociated.")
            return
        else:
            time.sleep(60)
            timepassed += 60
            if timepassed >= timeout:
                print ("timed out waiting for dissassociation of physical server: "+phy_server_dn)
                sys.exit()


def delete_org(ucs_handle, org_name):
    filter_str = "(name, \""+org_name+"\")"
    org_object = ucs_handle.query_classid(class_id="orgOrg", filter_str=filter_str)[0]
    ucs_handle.remove_mo(org_object)
    ucs_handle.commit()


def ucs_disconnect(ucs_handle):
    ucs_handle.logout()


def vcenter_connect(vcenter_ip, vcenter_user, vcenter_pass):
    vcenter_handle = connect.SmartConnectNoSSL(host=vcenter_ip, user=vcenter_user, pwd=vcenter_pass)
    return vcenter_handle


def get_cluster(vcenter_handle, vcenter_dc, vcenter_cluster):
    clusters = vcenter_handle.content.viewManager.CreateContainerView(vcenter_handle.content.rootFolder, [vim.ClusterComputeResource], True)
    for cluster_object in clusters.view:
        if cluster_object.name == vcenter_cluster and cluster_object.parent.parent.name == vcenter_dc:
            return cluster_object

def dc_exists(vcenter_handle, vcenter_dc):
    datacenters = vcenter_handle.content.viewManager.CreateContainerView(vcenter_handle.content.rootFolder, [vim.Datacenter], True)
    for dc in datacenters.view:
        if dc.name == vcenter_dc:
            return True
    return False


def cluster_exists(vcenter_handle, vcenter_dc, vcenter_cluster):
    clusters = vcenter_handle.content.viewManager.CreateContainerView(vcenter_handle.content.rootFolder, [vim.ClusterComputeResource], True)
    for cluster in clusters.view:
        if cluster.name == vcenter_cluster and cluster.parent.parent.name == vcenter_dc:
            return True
    return False


def delete_vcenter_cluster(vcenter_handle, cluster_object):
    cluster_object.Destroy()


def delete_vcenter_extension(vcenter_handle, ext_name):
    extensions = vcenter_handle.content.extensionManager.extensionList
    for ext in extensions:
        if ext_name in ext.key:
            vcenter_handle.content.extensionManager.UnregisterExtension(ext_name)


def get_hx_extensions(vcenter_handle):
    extensions = vcenter_handle.content.extensionManager.extensionList
    hx_extensions = []
    for ext in extensions:
        if "springpath" in ext.key:
            hx_extensions.append(ext.key)
    return hx_extensions


def vcenter_disconnect(vcenter_handle):
    connect.Disconnect(vcenter_handle)


def get_intersight_handle(intersight_api_file):
    with open(intersight_api_file, 'r') as api_file:
        intersight_api_params = json.load(api_file)

    private_key=intersight_api_params['api_private_key_file']
    api_key_id=intersight_api_params['api_key_id']

    intersight_handle.set_private_key(open(private_key, "r") .read())
    intersight_handle.set_public_key(api_key_id.rstrip())

    return intersight_handle


def test_intersight_handle(intersight_handle):

    resource_path = '/ntp/Policies'
    query_params = {}

    options = {
        "http_method":"get",
        "resource_path":resource_path,
        "query_params":query_params
    }

    results = intersight_handle.intersight_call(**options)
    if results.status_code == 200:
        return False
    else:
        print (Fore.RED+"There was a problem connecting to Intersight. Check internet connectivity and the API key file and then try again."+Style.RESET_ALL)
        print ("\n")


def send_intersight_api(method,resource_path,query_params,moid=None,body=None,intersight_handle=intersight_handle):

    if method == "get":
        options = {
            "http_method":"get",
            "resource_path":resource_path,
            "query_params":query_params
        }
    elif method == "patch":
        options = {
            "http_method":"patch",
            "resource_path":resource_path,
            "body":body,
            "moid":moid
        }
    elif method == "delete":
        options = {
            "http_method":"delete",
            "resource_path":resource_path,
            "moid":moid
        }

    try:
        results = intersight_handle.intersight_call(**options)
        if results.status_code == 200:
            return results.json()
        else:
            raise Exception
    except Exception as e:
        print (Fore.RED+"There was a problem sending api call to Intersight"+Style.RESET_ALL)
        print (e)
        print (results)


def does_intersight_cluster_exist(intersight_cluster_profile_name):

    method = "get"
    resource_path = '/hyperflex/ClusterProfiles'
    query_params = {
        "$filter":"Name eq '%s'" % intersight_cluster_profile_name
    }

    results = send_intersight_api(method, resource_path, query_params)
    if results['Results'][0]['Name'] == intersight_cluster_profile_name:
        return True
    else:
        return False


def get_intersight_cluster_profile_moid(intersight_cluster_profile_name):

    method = "get"
    resource_path = '/hyperflex/ClusterProfiles'
    query_params = {
        "$select":"Moid",
        "$filter":"Name eq '%s'" % intersight_cluster_profile_name
    }

    results = send_intersight_api(method, resource_path, query_params)
    intersight_cluster_profile_moid = results['Results'][0]['Moid']
    return intersight_cluster_profile_moid


def get_device_ip_list_by_cluster_name(intersight_cluster_profile_name):

    # Get hx cluster profile
    method = "get"
    resource_path = '/hyperflex/ClusterProfiles'
    query_params = {
        "$filter":"Name eq '%s'" % intersight_cluster_profile_name
    }

    results = send_intersight_api(method, resource_path, query_params)

    # Get list of node profile moids
    node_profile_configs = results['Results'][0]['NodeProfileConfig']
    node_profile_moid_list = []
    for node_profile in node_profile_configs:
        node_profile_moid_list.append(node_profile['Moid'])

    #Create empty list for device ips
    device_ip_list = []

    #Iterate through each node profile
    for node_profile_moid in node_profile_moid_list:

        #Get rack unit moid
        method = "get"
        resource_path = '/hyperflex/NodeProfiles/'+node_profile_moid
        query_params = {}

        results = send_intersight_api(method, resource_path, query_params)
        rack_unit_moid = results['AssignedServer']['Moid']

        #Get asset device moid
        method = "get"
        resource_path = '/compute/RackUnits/'+rack_unit_moid
        query_params = {}

        results = send_intersight_api(method, resource_path, query_params)
        asset_device_moid = results['RegisteredDevice']['Moid']


        #Get device ip
        method = "get"
        resource_path = '/asset/DeviceRegistrations/'+asset_device_moid
        query_params = {}

        results = send_intersight_api(method, resource_path, query_params)
        device_ip = results['DeviceIpAddress'][0]
        device_ip_list.append(device_ip)
    return device_ip_list


def intersight_cluster_profile_unassign_nodes(intersight_cluster_profile_moid):

    method = "patch"
    resource_path = '/hyperflex/ClusterProfiles'
    query_params = {}

    body = {
        'Action':'Unassign'
    }

    results = send_intersight_api(method, resource_path, query_params, intersight_cluster_profile_moid, body)


def delete_intersight_hyperflex_cluster(intersight_cluster_profile_moid):

    method = "get"
    resource_path = '/asset/DeviceRegistrations'
    query_params = {
        "$filter":"PlatformType eq 'HX' and DeviceHostname eq '%s'" % intersight_cluster_profile_name
    }

    results = send_intersight_api(method, resource_path, query_params)
    device_claim_moid = results['Results'][0]['DeviceClaim']['Moid']

    method = "delete"
    resource_path = '/asset/DeviceClaims'
    query_params = {}

    results = send_intersight_api(method, resource_path, query_params, device_claim_moid)


def cimc_connect(cimc_ip_address, cimc_user, cimc_pass):
    cimc_handle = ImcHandle(cimc_ip_address, cimc_user, cimc_pass)
    cimc_handle.login()
    return cimc_handle


def cimc_power_action(cimc_handle, action):
    mo = cimc_handle.query_dn('sys/rack-unit-1')
    if action == "off":
        mo.admin_power = 'down'
    elif action == "shutdown":
        mo.admin_power = 'soft-shut-down'
    elif action == "on":
        mo.admin_power = 'up'
    cimc_handle.set_mo(mo)


def get_cimc_power_state(cimc_handle):
    mo = cimc_handle.query_dn('sys/rack-unit-1')
    power_state = mo.oper_power
    return power_state


def create_cimc_vmedia_mount(cimc_handle, cimc_vmedia_share, cimc_vmedia_filename, cimc_vmedia_type, cimc_vmedia_user=None, cimc_vmedia_pass=None):
    if cimc_vmedia_type == "nfs":
        lsboot_vmedia_policy = CommVMediaMap(parent_mo_or_dn='sys/svc-ext/vmedia-svc',volume_name='hxesxi',remote_share=cimc_vmedia_share,remote_file=cimc_vmedia_filename,map=cimc_vmedia_type)
    elif cimc_vmedia_type == "cifs" or cimc_vmedia_type == "www":
        if cimc_vmedia_user is not None:
            lsboot_vmedia_policy = CommVMediaMap(parent_mo_or_dn='sys/svc-ext/vmedia-svc',volume_name='hxesxi',remote_share=cimc_vmedia_share,remote_file=cimc_vmedia_filename,map=cimc_vmedia_type,username=cimc_vmedia_user,password=cimc_vmedia_pass)
        else:
            lsboot_vmedia_policy = CommVMediaMap(parent_mo_or_dn='sys/svc-ext/vmedia-svc',volume_name='hxesxi',remote_share=cimc_vmedia_share,remote_file=cimc_vmedia_filename,map=cimc_vmedia_type)
    cimc_handle.add_mo(lsboot_vmedia_policy)


def delete_cimc_vmedia_mount(cimc_handle):
    lsboot_vmedia_policy = cimc_handle.query_dn('sys/svc-ext/vmedia-svc/vmmap-hxesxi')
    cimc_handle.remove_mo(lsboot_vmedia_policy)



def set_cimc_boot_policy(cimc_handle):
    lsboot_vmedia_boot_order = LsbootVirtualMedia(parent_mo_or_dn='sys/rack-unit-1/boot-policy',type='virtual-media',order='1',access='read-only')
    cimc_handle.add_mo(lsboot_vmedia_boot_order)
    lsboot_storage_boot_order = LsbootStorage(parent_mo_or_dn='sys/rack-unit-1/boot-policy',type='storage',order='2',access='read-write')
    cimc_handle.add_mo(lsboot_storage_boot_order)


def monitor_cimc_esxi_prompt(cimc_ip):
    ssh_newkey = "Are you sure you want to continue connecting"
    cmd = "ssh -l %s %s -oKexAlgorithms=diffie-hellman-group1-sha1,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" % (cimc_user, cimc_ip)
    kvm_session = pexpect.spawn(cmd, timeout=600)
    kvm_session.timeout=600
    i = kvm_session.expect([ssh_newkey, '[Pp]assword:'])
    if i == 0:
        kvm_session.sendline("yes")
        kvm_session.expect("[Pp]assword:")
    time.sleep(5)
    kvm_session.sendline(cimc_pass)
    kvm_session.expect("#")
    kvm_session.sendline("connect host")
    kvm_session.expect("Connection to Exit|Exit the session")
    kvm_session.sendcontrol('d')
    time.sleep(10)
    kvm_session.expect("login:")
    time.sleep(10)
    kvm_session.sendline("root")
    kvm_session.expect("[Pp]assword:")
    kvm_session.sendline("Cisco123")
    kvm_session.expect(":~]")
    print ("   <> Successfully connected to ESXi CLI prompt on CIMC: "+cimc_ip)


def get_cimc_ip(cimc_handle):
    mo=cimc_handle.query_dn('sys/rack-unit-1/mgmt/if-1')
    power_state = mo.ext_ip
    return power_state


def cimc_disconnect(cimc_handle):
    cimc_handle.logout()



##################
# MAIN ###########
##################

print ("\n")
print (Style.BRIGHT+"WARNING!!!"+Style.RESET_ALL)
print ("The following script will completely erase a HyperFlex configuration including the data, which will not be recoverable afterwards.")
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"TASK 1: Get Environment Details"+Style.RESET_ALL)
print ("\n")


while True:

    print (Style.BRIGHT+Fore.WHITE+"Choose the number that best describes your HyperFlex cluster:"+Style.RESET_ALL)
    print ("\n")
    print ("     1. Standard HyperFlex connected to Intersight")
    print ("     2. Standard HyperFlex not connected to Intersight")
    print ("     3. HyperFlex Edge connected to Intersight")
    print ("     4. HyperFlex Edge not connected Intersight")
    print("\n")
    cluster_type = input(Style.BRIGHT+Fore.WHITE+"     Selection: "+Style.RESET_ALL)
    if cluster_type in ("1","2","3","4"):
        break
    else:
        print ("   <> Not a valid entry, please retry...")

print ("\n")


##############################
# Gather Intersight API Details
##############################


if cluster_type in ("1","3"):


    print (Style.BRIGHT+Fore.CYAN+"Gathering Intersight API Details..."+Style.RESET_ALL)
    print ("\n")

    while True:
        intersight_api_file = input(Style.BRIGHT+Fore.WHITE+"Please enter the name of the API key file: "+Style.RESET_ALL)
        if path.exists(intersight_api_file):
            intersight_handle = get_intersight_handle(intersight_api_file)
            test_intersight_handle(intersight_handle)
            print ("   <> Found API key file and able to connect to Intersight.")
            print ("      "+u'\U0001F44D'+" Done.")
            print ("\n")
            break
        else:
            print ("   <> Unable to locate provided API key file. please retry...")
            print ("\n")

    while True:
        intersight_cluster_profile_name = input(Style.BRIGHT+Fore.WHITE+"Please enter the name of the HyperFlex cluster in Intersight: "+Style.RESET_ALL)
        intersight_cluster_exists = does_intersight_cluster_exist(intersight_cluster_profile_name)
        if intersight_cluster_exists == True:
            print ("   <> Successfully found HyperFlex cluster in Intersight.")
            print ("      "+u'\U0001F44D'+" Done.")
            break
        else:
            print ("   <> Unable to find specified HyperFlex cluster in Intersight. Please check Intersight or re-enter cluster name...")
    print ("\n")


##############################
# Gather UCSM Details ########
##############################


if cluster_type in ("1","2"):

    from ucsmsdk.ucshandle import UcsHandle
    from ucsmsdk.mometa.lsboot.LsbootPolicy import LsbootPolicy
    from ucsmsdk.mometa.lsboot.LsbootVirtualMedia import LsbootVirtualMedia
    from ucsmsdk.mometa.lsboot.LsbootEmbeddedLocalDiskImage import LsbootEmbeddedLocalDiskImage
    from ucsmsdk.mometa.lsboot.LsbootUsbFlashStorageImage import LsbootUsbFlashStorageImage
    from ucsmsdk.mometa.ls.LsPower import LsPower

    print (Style.BRIGHT+Fore.CYAN+"Gathering UCS Details..."+Style.RESET_ALL)
    print ("\n")

    while True:
        ucsm_ip = input(Style.BRIGHT+Fore.WHITE+"Please enter the UCS Manager IP address: "+Style.RESET_ALL)
        ucsm_user = input(Style.BRIGHT+Fore.WHITE+"Please enter the UCS Manager username: "+Style.RESET_ALL)
        ucsm_pass = getpass.getpass(Style.BRIGHT+Fore.WHITE+"Please enter the UCS Manager password: "+Style.RESET_ALL)
        try:
            ucs_handle = ucs_connect(ucsm_ip, ucsm_user, ucsm_pass)
            if ucs_handle:
                print ("   <> Successfully connected to UCS Manager.")
                print ("      "+u'\U0001F44D'+" Done.")
                break
        except:
            print ("   <> Unable to connect to UCS Mananger with the provided details, please retry...")

    while True:
        org_name = input(Style.BRIGHT+Fore.WHITE+"Please enter the UCS Org associated with the HyperFlex cluster: "+Style.RESET_ALL)
        if org_exists(ucs_handle, org_name):
            print ("   <> Successfully found UCS Org.")
            print ("      "+u'\U0001F44D'+" Done.")
            break
        else:
            print ("   <> Provided UCS Org does not exist, please retry...")

    while True:
        vmedia_policy_name = input(Style.BRIGHT+Fore.WHITE+"Please enter the UCS vMedia policy name to be used for re-imaging the HyperFlex nodes: "+Style.RESET_ALL)
        if vmedia_policy_exists(ucs_handle, vmedia_policy_name):
            print ("   <> Successfully found vMedia policy.")
            print ("      "+u'\U0001F44D'+" Done.")
            break
        else:
            print ("   <> Provided UCS vMedia policy does not exist, please retry...")

    ucs_disconnect(ucs_handle)
    print ("\n")


##############################
# Gather CIMC Details
##############################


if cluster_type in ("3","4"):


    from imcsdk.imchandle import ImcHandle
    from imcsdk.mometa.comm.CommVMediaMap import CommVMediaMap
    from imcsdk.mometa.lsboot.LsbootVirtualMedia import LsbootVirtualMedia
    from imcsdk.mometa.lsboot.LsbootStorage import LsbootStorage
    from imcsdk.mometa.compute.ComputeRackUnit import ComputeRackUnit

    print (Style.BRIGHT+Fore.CYAN+"Gathering CIMC Details..."+Style.RESET_ALL)
    print ("\n")

    if cluster_type in ("3"):
        print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Getting list of CIMC IP addresses from Intersight..."+Style.RESET_ALL)
        cimc_ip_list = get_device_ip_list_by_cluster_name(intersight_cluster_profile_name)
        for cimc_ip in cimc_ip_list:
            print ("   <> Item: HyperFlex Edge Node, CIMC IP: "+cimc_ip)
        print ("      "+u'\U0001F44D'+" Done.")
        print ("\n")

    elif cluster_type in ("4"):
        while True:
            input_cimc_ip_list = input(Style.BRIGHT+Fore.WHITE+"Please enter a comma seperated list of CIMC IP addresses (i.e. \"192.168.1.2,192.168.1.3,192.168.1.4\"): "+Style.RESET_ALL)
            raw_cimc_ip_list = input_cimc_ip_list.split(",")
            cimc_ip_list = []
            try:
                for raw_cimc_ip in raw_cimc_ip_list:
                    cimc_ip = raw_cimc_ip.replace(" ","")
                    IP(cimc_ip)
                    cimc_ip_list.append(cimc_ip)
                break
            except:
                print ("    <> Provided CIMC IP: "+cimc_ip+" does not appear to be a valid IPv4 address, please retry...")


    while True:
        cimc_user = input(Style.BRIGHT+Fore.WHITE+"Please enter the HyperFlex Edge node's CIMC username: "+Style.RESET_ALL)
        cimc_pass = getpass.getpass(Style.BRIGHT+Fore.WHITE+"Please enter the HyperFlex Edge node's CIMC password: "+Style.RESET_ALL)
        try:
            cimc_handle = cimc_connect(cimc_ip_list[0], cimc_user, cimc_pass)
            if cimc_connect:
                print ("   <> Successfully connected to CIMC using provided credentials")
                cimc_disconnect(cimc_handle)
                print ("      "+u'\U0001F44D'+" Done.")
                break
        except:
            print ("   <> Unable to connect to CIMC with the provided credentials, please retry...")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"Gathering HyperFlex ESXi ISO vMedia Details..."+Style.RESET_ALL)
    print ("\n")


    while True:
        cimc_vmedia_type = input(Style.BRIGHT+Fore.WHITE+"Please enter the Share type (options: \"nfs\", \"cifs\" or \"www\"): "+Style.RESET_ALL)
        if cimc_vmedia_type in ("nfs","NFS","cifs","CIFS","www","WWW"):
            break
        else:
            print ("   <> Share type entered not valid, please retry...")
    cimc_vmedia_share = input(Style.BRIGHT+Fore.WHITE+"Please enter the Remote Share location (i.e. \"10.1.8.3:/isos\"): "+Style.RESET_ALL)
    cimc_vmedia_filename = input(Style.BRIGHT+Fore.WHITE+"Please enter the full filename of the HyperFlex ESXi ISO image on the Remote Share: "+Style.RESET_ALL)
    if cimc_vmedia_type == "cifs" or cimc_vmedia_type == "www":
        while True:
            user_prompt = input(Style.BRIGHT+Fore.WHITE+"Do you need to enter a Username and Password to access the Remote Share? (y/n): "+Style.RESET_ALL)
            if user_prompt in ("y","Y","n","N"):
                cimc_vmedia_user = input(Style.BRIGHT+Fore.WHITE+"Enter Remote Share username: "+Style.RESET_ALL)
                cimc_vmedia_pass = getpass.getpass(Style.BRIGHT+Fore.WHITE+"Enter Remote Share password: "+Style.RESET_ALL)
                break
            else:
                print ("   <> Not a valid response, please retry...")
    print ("\n")



##############################
# Gather vCenter  Details
##############################


print (Style.BRIGHT+Fore.CYAN+"Gathering vCenter Details..."+Style.RESET_ALL)
print ("\n")

while True:
    vcenter_ip = input(Style.BRIGHT+Fore.WHITE+"Please enter the vCenter IP address: "+Style.RESET_ALL)
    vcenter_user = input(Style.BRIGHT+Fore.WHITE+"Please enter the vCenter username: "+Style.RESET_ALL)
    vcenter_pass = getpass.getpass(Style.BRIGHT+Fore.WHITE+"Please enter the vCenter password: "+Style.RESET_ALL)
    try:
        vcenter_handle = vcenter_connect(vcenter_ip, vcenter_user, vcenter_pass)
        if vcenter_handle:
            print ("   <> Successfully connected to vCenter.")
            break
    except:
        print ("   <> Unable to connect to vCenter with the provided details, please retry...")

while True:
    vcenter_dc = input(Style.BRIGHT+Fore.WHITE+"Please enter the VMware Datacenter name containing the HyperFlex cluster: "+Style.RESET_ALL)
    if dc_exists(vcenter_handle, vcenter_dc):
        print ("   <> Successfully found VMware Datacenter.")
        break
    else:
        print ("   <> Provided VMware Datacenter does not exist, please retry...")

while True:
    vcenter_cluster = input(Style.BRIGHT+Fore.WHITE+"Please enter the VMware Cluster name associated with the HyperFlex cluster: "+Style.RESET_ALL)
    if cluster_exists(vcenter_handle, vcenter_dc, vcenter_cluster):
        print ("   <> Successfully found VMware Cluster.")
        break
    else:
        print ("   <> Provided VMware Cluster does not exist, please retry...")

vcenter_disconnect(vcenter_handle)
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"TASK COMPLETED: Get Environment Details"+Style.RESET_ALL)
print ("\n")


##############################
# Re-Image UCS Managed HyperFlex Nodes
##############################


if cluster_type in ("1","2"):


    print (Style.BRIGHT+Fore.GREEN+"TASK: Re-image HyperFlex Nodes"+Style.RESET_ALL)
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Connecting to UCS Manager..."+Style.RESET_ALL)
    ucs_handle = ucs_connect(ucsm_ip, ucsm_user, ucsm_pass)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Fetching service profiles in the provided ucs org..."+Style.RESET_ALL)
    sp_objects = get_sps_in_org(ucs_handle, org_name)
    for sp_object in sp_objects:
        print ("   <> Item: Service Profile, Name: "+sp_object.name+", DN: "+sp_object.dn)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Fetching related service profile template..."+Style.RESET_ALL)
    sp_template_dn = get_sp_template_dn(ucs_handle, sp_objects[0])
    sp_template_object = get_ucs_object_by_dn(ucs_handle, sp_template_dn)
    print ("   <> Item: Service Profile Template, Name: "+sp_template_object.name+", DN: "+sp_template_object.dn)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Fetching related service profile template boot policy information..."+Style.RESET_ALL)
    sp_template_boot_policy_dn = get_sp_template_boot_policy_dn(ucs_handle, sp_template_object)
    sp_template_boot_policy_object = get_ucs_object_by_dn(ucs_handle, sp_template_boot_policy_dn)
    print ("   <> Item: Service Profile Template Boot Policy, Name: "+sp_template_boot_policy_object.name+", DN: "+sp_template_boot_policy_object.dn)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Fetching current service profile template vmedia policy information..."+Style.RESET_ALL)
    sp_template_vmedia_policy_dn = get_sp_template_vmedia_policy_dn(ucs_handle, sp_template_object)
    if not sp_template_vmedia_policy_dn:
        print ("   <> Item: Service Profile Template vMedia Policy, Name: <None>, DN: <None>")
    else:
        sp_template_vmedia_policy_object = get_ucs_object_by_dn(ucs_handle, sp_template_vmedia_policy_dn)
        print ("   <> Item: Current Service Profile Template vMedia Policy, Name: "+sp_template_vmedia_policy_object.name+", DN: "+sp_template_vmedia_policy_object.dn)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Setting new service profile template vmedia policy..."+Style.RESET_ALL)
    sp_template_object = set_sp_template_vmedia_policy(ucs_handle, sp_template_object, vmedia_policy_name)
    sp_template_vmedia_policy_dn = get_sp_template_vmedia_policy_dn(ucs_handle, sp_template_object)
    sp_template_vmedia_policy_object = get_ucs_object_by_dn(ucs_handle, sp_template_vmedia_policy_dn)
    print ("   <> Item: New Service Profile Template vMedia Policy, Name: "+sp_template_vmedia_policy_object.name+", DN: "+sp_template_vmedia_policy_object.dn)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Setting vmedia policy as first boot item in service profile template boot policy..."+Style.RESET_ALL)
    set_vmedia_boot_policy(ucs_handle, sp_template_boot_policy_object, org_name)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Rebooting service profiles in provided ucs org..."+Style.RESET_ALL)
    for sp_object in sp_objects:
        sp_power_action(ucs_handle, sp_object.dn, "hard-reset-immediate")
        print ("   <> Rebooting service profile: "+sp_object.name)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Disconnecting from UCS Manager..."+Style.RESET_ALL)
    ucs_disconnect(ucs_handle)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Going to sleep while HyperFlex nodes are re-imaged, this can take ~25-30 minutes due to multiple required reboots during install..."+Style.RESET_ALL)
    for i in xrange(500,0,-1):
        sys.stdout.write(str('.'))
        sys.stdout.flush()
        time.sleep(3)
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Waking up..."+Style.RESET_ALL)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Connecting to UCS Manager..."+Style.RESET_ALL)
    ucs_handle = ucs_connect(ucsm_ip, ucsm_user, ucsm_pass)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Getting service profile kvm ip addresses..."+Style.RESET_ALL)
    sp_objects = get_sps_in_org(ucs_handle, org_name)
    sp_kvm_ips = get_sp_kvm_ips(ucs_handle, sp_objects)
    for key, value in sp_kvm_ips.iteritems():
        print ("   <> Item: Service Profile, Name: "+key+", KVM IP: "+value)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Waiting for access to ESXi CLI prompt for service profiles, this can take another couple of minutes..."+Style.RESET_ALL)
    threads = []
    for key, value in sp_kvm_ips.iteritems():
        print ("   <> Waiting to connect to ESXi CLI prompt on service profile: "+key)
        thread = Thread(target=monitor_esxi_prompt, args=(key, value,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Gracefully powering-off service profiles..."+Style.RESET_ALL)
    for sp_object in sp_objects:
        sp_power_action(ucs_handle, sp_object.dn, "soft-shut-down-only")
        print ("   <> Powering-off service profile: "+sp_object.name)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.GREEN+"TASK COMPLETED: Re-image HyperFlex Nodes"+Style.RESET_ALL)
    print ("\n")


##############################
# Clean Up UCS Manager Config
##############################


    print (Style.BRIGHT+Fore.GREEN+"TASK: Clean-up HyperFlex Config in UCS Manager"+Style.RESET_ALL)
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Getting list of physical rack servers supporting HyperFlex service profiles..."+Style.RESET_ALL)
    phy_server_dns = get_phys_server_dns(ucs_handle, sp_objects)
    for phy_server in phy_server_dns:
        print ("   <> Item: Physical Server, DN: "+phy_server)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Deleting org \""+org_name+"\" in UCS Manager..."+Style.RESET_ALL)
    delete_org(ucs_handle, org_name)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Waiting for complete dissassociation of physical servers..."+Style.RESET_ALL)
    threads = []
    for phy_server in phy_server_dns:
        thread = Thread(target=monitor_phy_server_assoc, args=(ucs_handle, phy_server,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()



    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Disconnecting from UCS Manager..."+Style.RESET_ALL)
    ucs_disconnect(ucs_handle)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.GREEN+"TASK COMPLETED: Clean-up HyperFlex Config in UCS Manager"+Style.RESET_ALL)
    print ("\n")


##############################
# Re-Image HyperFlex Edge Nodes
##############################


if cluster_type in ("3","4"):

    print (Style.BRIGHT+Fore.GREEN+"TASK: Re-Image HyperFlex Edge Nodes"+Style.RESET_ALL)
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Connecting to CIMC interfaces of HyperFlex Edge nodes..."+Style.RESET_ALL)
    cimc_handle_list = []
    for cimc_ip in cimc_ip_list:
        cimc_handle = cimc_connect(cimc_ip, cimc_user, cimc_pass)
        cimc_handle_list.append(cimc_handle)
        print ("   <> Item: HyperFlex Edge Node CIMC: "+cimc_ip+", Connected: True")
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Powering-off HyperFlex Edge nodes..."+Style.RESET_ALL)
    for cimc_handle in cimc_handle_list:
        cimc_power_action(cimc_handle, "off")
    for cimc_handle in cimc_handle_list:
        while True:
            cimc_power_state = get_cimc_power_state(cimc_handle)
            cimc_ip = get_cimc_ip(cimc_handle)
            if cimc_power_state == "off":
                print ("   <> Item: HyperFlex Edge Node CIMC: "+cimc_ip+", Power State: off")
                break
            else:
                time.sleep(5)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Creating vMedia Mount on HyperFlex Edge nodes..."+Style.RESET_ALL)
    for cimc_handle in cimc_handle_list:
        create_cimc_vmedia_mount(cimc_handle, cimc_vmedia_share, cimc_vmedia_filename, cimc_vmedia_type)
        cimc_ip = get_cimc_ip(cimc_handle)
        print ("   <> Item: HyperFlex Edge Node CIMC: "+cimc_ip+", vMedia Mount Created: True")
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Modifying Boot Policy on HyperFlex Edge nodes..."+Style.RESET_ALL)
    for cimc_handle in cimc_handle_list:
        set_cimc_boot_policy(cimc_handle)
        cimc_ip = get_cimc_ip(cimc_handle)
        print ("   <> Item: HyperFlex Edge Node CIMC: "+cimc_ip+", Boot Policy Modified: True")
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Powering-on HyperFlex Edge nodes..."+Style.RESET_ALL)
    for cimc_handle in cimc_handle_list:
        cimc_power_action(cimc_handle, "on")
    for cimc_handle in cimc_handle_list:
        while True:
            cimc_power_state = get_cimc_power_state(cimc_handle)
            cimc_ip = get_cimc_ip(cimc_handle)
            if cimc_power_state == "on":
                print ("   <> Item: HyperFlex Edge Node CIMC: "+cimc_ip+", Power State: on")
                break
            else:
                time.sleep(5)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Disconnecting from CIMCs..."+Style.RESET_ALL)
    for cimc_handle in cimc_handle_list:
        cimc_disconnect(cimc_handle)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Going to sleep while HyperFlex nodes are re-imaged, this can take ~25-30 minutes due to multiple required reboots during install..."+Style.RESET_ALL)
    for i in xrange(600,0,-1):
        sys.stdout.write(str('.'))
        sys.stdout.flush()
        time.sleep(3)
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Waking up..."+Style.RESET_ALL)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Connecting to CIMC interfaces of HyperFlex Edge nodes..."+Style.RESET_ALL)
    cimc_handle_list = []
    for cimc_ip in cimc_ip_list:
        print ("   <> Connected to CIMC IP: "+cimc_ip)
        cimc_handle = cimc_connect(cimc_ip, cimc_user, cimc_pass)
        cimc_handle_list.append(cimc_handle)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Waiting for access to ESXi CLI prompt for service profiles, this can take another couple of minutes..."+Style.RESET_ALL)
    threads = []
    for cimc_ip in cimc_ip_list:
        print ("   <> Waiting to connect to ESXi CLI prompt on CIMC IP: "+cimc_ip)
        thread = Thread(target=monitor_cimc_esxi_prompt, args=(cimc_ip,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Gracefully Shutting Down HyperFlex Edge nodes..."+Style.RESET_ALL)
    for cimc_handle in cimc_handle_list:
        cimc_power_action(cimc_handle, "shutdown")
    for cimc_handle in cimc_handle_list:
        while True:
            cimc_power_state = get_cimc_power_state(cimc_handle)
            cimc_ip = get_cimc_ip(cimc_handle)
            if cimc_power_state == "off":
                print ("   <> Item: HyperFlex Edge Node CIMC: "+cimc_ip+", Power State: off")
                break
            else:
                time.sleep(5)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Deleting vMedia Mount on HyperFlex Edge nodes..."+Style.RESET_ALL)
    for cimc_handle in cimc_handle_list:
        delete_cimc_vmedia_mount(cimc_handle)
        print ("   <> Item: HyperFlex Edge Node CIMC: "+cimc_ip+", vMedia Mount Deleted: True")
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.GREEN+"TASK COMPLETED: Re-Image HyperFlex Edge Nodes"+Style.RESET_ALL)
    print ("\n")


##############################
# Clean Up Intersight
##############################

if cluster_type in ("1","3"):


    print (Style.BRIGHT+Fore.GREEN+"TASK: Clean-up HyperFlex Config in Intersight"+Style.RESET_ALL)
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Unassigning Nodes from HyperFlex Cluster Profile..."+Style.RESET_ALL)
    cluster_profile = get_intersight_cluster_profile(api_instance, intersight_cluster_profile_name)
    intersight_cluster_profile_unassign_nodes(api_instance, cluster_profile)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")


    print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Deleteing HyperFlex Cluster Device from Intersight Device List..."+Style.RESET_ALL)
    delete_intersight_device(api_instance, intersight_cluster_profile_name)
    print ("      "+u'\U0001F44D'+" Done.")
    print ("\n")

    print (Style.BRIGHT+Fore.GREEN+"TASK COMPLETED: Clean-up HyperFlex Config in Intersight"+Style.RESET_ALL)
    print ("\n")



##############################
# Clean Up vCenter Config
##############################


print (Style.BRIGHT+Fore.GREEN+"TASK: Clean-up HyperFlex Config in vCenter"+Style.RESET_ALL)
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Connecting to vCenter..."+Style.RESET_ALL)
vcenter_handle = vcenter_connect(vcenter_ip, vcenter_user, vcenter_pass)
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Deleting HyperFlex vCenter extensions..."+Style.RESET_ALL)
cluster_object = get_cluster(vcenter_handle, vcenter_dc, vcenter_cluster)
cluster_ext_name = "com.springpath.sysmgmt."+cluster_object._moId
delete_vcenter_extension(vcenter_handle, cluster_ext_name)
hx_extensions = get_hx_extensions(vcenter_handle)
if len(hx_extensions) == 1 and hx_extensions[0] == "com.springpath.sysmgmt":
    print ("   <> Only one HyperFlex cluster found, also deleting \"com.springpath.sysmgmt\" extension.")
    delete_vcenter_extension(vcenter_handle, "com.springpath.sysmgmt")
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.CYAN+"-->"+Fore.WHITE+" Deleting HyperFlex ESXi cluster in vCenter..."+Style.RESET_ALL)
cluster_object.Destroy()
print ("      "+u'\U0001F44D'+" Done.")
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"TASK 4 COMPLETED: Clean-up HyperFlex Config in vCenter"+Style.RESET_ALL)
print ("\n")


print (Style.BRIGHT+Fore.GREEN+"HyperFlex Reset Completed!!!"+Style.RESET_ALL)
print ("\n")
