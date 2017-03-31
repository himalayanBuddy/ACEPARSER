import ace2f5_parser as parsed_data
import parser_functions as function
import os
import sys

#This file is to create F5 configs from the data provided by the ace2f5_parser.py file


#Style one, All Configuration in Single File
style_type = 1

if style_type == 1:
    #Counts                
    node_count = 0
    pool_count = 0
    virtual_count = 0
    enabled_vlan = "Vlan888"
    #

    #Create a new file to write the configs along with other checks
    file_name = 'all_nodes_in_one.txt'
    path_to_folder = './F5Configs/'
    path_to_file = path_to_folder + file_name
    
    if (os.path.isdir(path_to_folder)):
        if(os.path.exists(path_to_file)):
            try:
                #First remove the file and create a new one
                os.remove(path_to_file)
                config_node_file = open(path_to_file, 'a')
            except OSError:
                pass
        else:
            config_node_file = open(path_to_file, 'a')

        #Read the VIPS to be migrated from the file provided
        inservice_file = sys.argv[2]
        in_read = open(inservice_file, 'r')
            

        #Create Node Configs
        for node_name, node_ip in sorted(parsed_data.rserver_ip_dict.items()):
            node_name = str(node_name).lower()
            config_node_file.write("ltm node " + node_name + " {\n")
            config_node_file.write("    address " + node_ip + "\n")
            config_node_file.write("}\n")
            node_count += 1
            print ("Creating node " + node_name)
        #Close the Nodes File
        config_node_file.close()
        #Virtual Server and Pool Member Configs    
        for vip_name in in_read:
            vip_name = vip_name.replace('\n','')
            if vip_name.rstrip() in parsed_data.virtual_lbpolicy: 

                #Some Initial Parameters
                is_irule = False
                irule_name = ""
                is_default_pool = False
                default_pool_name = ""
                ssl_offload_clientside = False
                ssl_offload_serverside = False
                counter_outer_rule = 0
                sticky_virtual = False
                http_profile = False
                redirect_url_flag = False
                
                print ("Creating Virtual " + vip_name)
                
                #Query the POLICY FOR THE VIP
                policyname = parsed_data.virtual_lbpolicy[vip_name]
                #Virtual Server IP and Port
                if vip_name in parsed_data.virtual_ip_proto_port_dict:
                    (virtualserver_ip_address,virtualserver_protocol,virtualserver_port) = parsed_data.virtual_ip_proto_port_dict[vip_name][0]

                    #Mapping the Ports 
                    (virtualserver_port, vs_port_name)=function.port_mappings(virtualserver_port)

                    #Lookup the DNS name to get use it as virtual server name
                    (is_domain_lookup, virtual_initial_name) = function.dns_mappings(virtualserver_ip_address)
                    if not is_domain_lookup:
                        virtual_initial_name = vip_name

                    #Name of the VIRTUAL SERVER and Destination in LTM Format   
                    virtual_server_name = virtual_initial_name + "-" + vs_port_name + "-vs"
                    virtual_destination = virtualserver_ip_address + ":" + virtualserver_port
                    
                    #Check SSL OFFLOADS on VIP
                    if vip_name in parsed_data.ssl_client_virtual_dict:
                        ssl_offload_clientside = True
                    if policyname in parsed_data.ssl_server_virtual_dict:
                        ssl_offload_serverside = True

                    #Individual Files For each Virtual Server
                    virtual_server_file_name = vip_name +".txt"
                    path_to_virtual_file = path_to_folder + virtual_server_file_name
                    if(os.path.exists(path_to_virtual_file)):
                        try:
                            #First remove the file and create a new one
                            os.remove(path_to_virtual_file)
                            config_file = open(path_to_virtual_file, 'a')
                        except OSError:
                            pass
                    else:
                        config_file = open(path_to_virtual_file, 'a')
                    

                        
                    
                    if len(parsed_data.pol_serverfarm_dict[policyname]) == 1:
                    #Pool Members
                        if parsed_data.pol_serverfarm_dict[policyname][0][1] in parsed_data.serverferm_details_rserver_dict:
                            (poolmember_lb_method, poolmember_monitor_name, pool_members) = parsed_data.serverferm_details_rserver_dict[parsed_data.pol_serverfarm_dict[policyname][0][1]]


                            #Default Pool Namings
                            default_pool_name = virtual_initial_name + "-" + vs_port_name+ "-pool"  
                            is_default_pool = True

                            #Load Balancing Mode
                            load_balancing_mode = function.lb_algorithm_mappings(poolmember_lb_method)


                            #MONITOR#
                            new_monitor_name = virtual_initial_name + "-" + vs_port_name + "-mon"
                            monitor_name = function.probe_mappings(poolmember_monitor_name, config_file, parsed_data.probe_dict, new_monitor_name)
                            print (monitor_name)

                            #==================================================================================    

                            #Write
                            config_file.write("ltm pool " + default_pool_name + " {\n")
                            config_file.write("    load-balancing-mode " + load_balancing_mode + "\n")
                            config_file.write("    members {\n")
                        
                            for members in pool_members:
                                (node_name, node_port) = members
                                (node_port, node_port_name) = function.port_mappings(node_port)

                                #Remapping the node_port if virtualserver_port is not '0' changing node_port to virtualserver_port
                                if node_port == '0' and virtualserver_port != '0':
                                    node_port = virtualserver_port
                                if node_name not in parsed_data.rserver_ip_dict:
                                    pass
                                node_ip = parsed_data.rserver_ip_dict[node_name]
                                node_name = str(node_name).lower()

                                config_file.write("        " + node_name + ":" + node_port + " {\n")
                                config_file.write("            address " + node_ip + "\n")
                                config_file.write("        }\n")
                            config_file.write("    }\n")                            
                            config_file.write("    monitor " + monitor_name + "\n")
                            config_file.write("    slow-ramp-time 30\n")
                            config_file.write("}\n")
                            pool_count += 1
                        
                        elif parsed_data.pol_serverfarm_dict[policyname][0][1] in parsed_data.sticky_serverfarm_dict:
                            #The virtual server has some sort of persistence
                            sticky_virtual = True
                            sticky_type = parsed_data.sticky_serverfarm_dict[parsed_data.pol_serverfarm_dict[policyname][0][1]][1]
                            sticky_value = parsed_data.sticky_serverfarm_dict[parsed_data.pol_serverfarm_dict[policyname][0][1]][2]

                            (persistence_profile, sticky_type) = function.persistence_mappings(sticky_type, sticky_value)

                            
                            if parsed_data.sticky_serverfarm_dict[parsed_data.pol_serverfarm_dict[policyname][0][1]][3] in parsed_data.serverferm_details_rserver_dict:
                                (poolmember_lb_method, poolmember_monitor_name, pool_members) = parsed_data.serverferm_details_rserver_dict[parsed_data.sticky_serverfarm_dict[parsed_data.pol_serverfarm_dict[policyname][
0][1]][3]]

                                #Default Pool Namings
                                default_pool_name = virtual_initial_name + "-" + vs_port_name+ "-pool"  
                                is_default_pool = True

                                #Load Balancing Mode
                                load_balancing_mode = function.lb_algorithm_mappings(poolmember_lb_method)


                                #Monitor - Will Refine this Later
                                new_monitor_name = virtual_initial_name + "-" + vs_port_name + "-mon"
                                monitor_name = function.probe_mappings(poolmember_monitor_name, config_file, parsed_data.probe_dict, new_monitor_name)
                                print (monitor_name)

                                #Write
                                config_file.write("ltm pool " + default_pool_name + " {\n")
                                config_file.write("    load-balancing-mode " + load_balancing_mode + "\n")
                                config_file.write("    members {\n")
                        
                                for members in pool_members:
                                    (node_name, node_port) = members
                                    (node_port, node_port_name) = function.port_mappings(node_port)

                                    #Remapping the node_port if virtualserver_port is not '0' changing node_port to virtualserver_port
                                    if node_port == '0' and virtualserver_port != '0':
                                        node_port = virtualserver_port                                    
                                    node_ip = parsed_data.rserver_ip_dict[node_name]
                                    node_name = str(node_name).lower()

                                    config_file.write("        " + node_name + ":" + node_port + " {\n")
                                    config_file.write("            address " + node_ip + "\n")
                                    config_file.write("        }\n")
                                config_file.write("    }\n")                            
                                config_file.write("    monitor " + monitor_name + "\n")
                                config_file.write("    slow-ramp-time 30\n")
                                config_file.write("}\n")
                                pool_count += 1
                             

                        elif parsed_data.pol_serverfarm_dict[policyname][0][1] in parsed_data.redirect_serverfarm_dict:
                            if parsed_data.redirect_serverfarm_dict[parsed_data.pol_serverfarm_dict[policyname][0][1]][0] in parsed_data.redirect_host_dict:
                                #print (parsed_data.redirect_host_dict[parsed_data.redirect_serverfarm_dict[parsed_data.pol_serverfarm_dict[policyname][0][1]][0]])
                                redirect_url = parsed_data.redirect_host_dict[parsed_data.redirect_serverfarm_dict[parsed_data.pol_serverfarm_dict[policyname][0][1]][0]]
                                redirect_url_flag = True

                    elif len(parsed_data.pol_serverfarm_dict[policyname]) > 1:
                        is_irule = True
                        irule_name = virtual_initial_name + "-" + "irule"
                        if parsed_data.pol_serverfarm_dict[policyname][0][1] in parsed_data.sticky_serverfarm_dict:
                            #Since In Sticky, Get the Sticky Details - Persistence
                            sticky_virtual = True
                            sticky_type = parsed_data.sticky_serverfarm_dict[parsed_data.pol_serverfarm_dict[policyname][0][1]][1]
                            sticky_value = parsed_data.sticky_serverfarm_dict[parsed_data.pol_serverfarm_dict[policyname][0][1]][2]
                            (persistence_profile, sticky_type) = function.persistence_mappings(sticky_type, sticky_value)
                            
                            #FOR IRULES======================================
                            for values in parsed_data.pol_serverfarm_dict[policyname]:
                                if values[0] in parsed_data.rule_class_map_dict:
                                    (rule_type, rule_method, value) = parsed_data.rule_class_map_dict[values[0]][0]
                                    break
                                else:
                                    pass
                                
                            #Write the RULE
                            if rule_type == "http" and rule_method == "url":
                                is_written = False
                                counter_outer_rule = 0
                                config_file.write("ltm rule " + irule_name + " {\n")
                                config_file.write("    when HTTP_REQUEST {\n")
                                config_file.write("        set uri [string tolower [HTTP::uri]]\n")
                                is_written = True
                                
                                for switches in parsed_data.pol_serverfarm_dict[policyname]:
                                    (switch_rule, serverfarm) = switches
                                    counter_inner_rule = 0
                                    
                                    if switch_rule in parsed_data.rule_class_map_dict:
                                        for (rule_type, rule_method, rule_value) in parsed_data.rule_class_map_dict[switch_rule]:
                                            if switch_rule == "class-default":
                                                default_pool_name = virtual_initial_name + "-" + vs_port_name+ "-pool"
                                                is_default_pool = True

                                            else:
                                                pool_name_split = switch_rule.split("-")
                                                if len(pool_name_split) > 1:
                                                    pool_name_init = pool_name_split[1]
                                                else:
                                                    pool_name_init = pool_name_split[0]
                                                irule_pool_name = virtual_initial_name + "-" + pool_name_init + "-pool"
                                                if is_written:
                                                    function.write_irule(rule_type, rule_method, rule_value, irule_pool_name, counter_outer_rule, counter_inner_rule, config_file)
                                                    counter_inner_rule += 1
                                        counter_outer_rule += 1

                            elif rule_type == "header" and rule_method == "Host":
                                print ("Irule with Host, Please Create")
                            elif rule_type == "source-address":
                                print ("Irule with Source Address Please Create")
                            elif rule_type == "url" and rule_method == "POST":
                                print ("Irule with POST, please Create")

                            #FOR IRULES END =======================================

                            #FOR POOL MEMBERS =====================================
                            for switches in parsed_data.pol_serverfarm_dict[policyname]:
                                (switch_rule, sticky_serverfarm) = switches
                                if parsed_data.sticky_serverfarm_dict[sticky_serverfarm][3] in parsed_data.serverferm_details_rserver_dict:
                                    (poolmember_lb_method, poolmember_monitor_name, pool_members) = parsed_data.serverferm_details_rserver_dict[parsed_data.sticky_serverfarm_dict[sticky_serverfarm][3]]

                                    #Namings
                                    if switch_rule == "class-default":
                                        default_pool_name = virtual_initial_name + "-" + vs_port_name+ "-pool"
                                        is_default_pool = True
                            
                                    else:
                                        pool_name_split = switch_rule.split("-")
                                        if len(pool_name_split) > 1:
                                            pool_name_init = pool_name_split[1]
                                        else:
                                            pool_name_init = pool_name_split[0]
                                            
                                        irule_pool_name =  virtual_initial_name + "-" + pool_name_init + "-pool"

                                    #Load Balancing Method
                                    load_balancing_mode = function.lb_algorithm_mappings(poolmember_lb_method)

                                    #Monitor
                                    new_monitor_name = virtual_initial_name + "-" + pool_name_init + "-mon"
                                    monitor_name = function.probe_mappings(poolmember_monitor_name, config_file, parsed_data.probe_dict, new_monitor_name)
                                    print (monitor_name)
                                    

                                    
                                    if poolmember_monitor_name == "HTTP-DataPowerStatus-Check":
                                        monitor_name = "datapowerstatus-http-mon"
                                    else:
                                        monitor_name ="tcp"
                                        
                                    if is_default_pool:    
                                        config_file.write("ltm pool " + default_pool_name + " {\n")
                                        config_file.write("    load-balancing-mode " + load_balancing_mode + "\n")
                                        config_file.write("    members {\n")
                                        for members in pool_members:
                                            (node_name, node_port) = members
                                            (node_port, node_port_name) = function.port_mappings(node_port)

                                            #Remapping the node_port if virtualserver_port is not '0' changing node_port to virtualserver_port
                                            if node_port == '0' and virtualserver_port != '0':
                                                node_port = virtualserver_port
                                            node_ip = parsed_data.rserver_ip_dict[node_name]
                                            node_name = str(node_name).lower()

                                            config_file.write("        " + node_name + ":" + node_port + " {\n")
                                            config_file.write("            address " + node_ip + "\n")
                                            config_file.write("        }\n")
                                        config_file.write("    }\n")                            
                                        config_file.write("    monitor " + monitor_name + "\n")
                                        config_file.write("    slow-ramp-time 30\n")
                                        config_file.write("}\n")
                                        pool_count += 1
                            #For POOL MEMBERS END
                        else:
                            #FOR IRULES
                            for values in parsed_data.pol_serverfarm_dict[policyname]:
                                if values[0] in parsed_data.rule_class_map_dict:
                                    (rule_type, rule_method, value) = parsed_data.rule_class_map_dict[values[0]][0]
                                    break
                                else:
                                    pass

                            #Write the RULE                               
                            if rule_type == "http" and rule_method == "url":
                                is_written = False
                                counter_outer_rule = 0
                                config_file.write("ltm rule " + irule_name + " {\n")
                                config_file.write("    when HTTP_REQUEST {\n")
                                config_file.write("        set uri [string tolower [HTTP::uri]]\n")
                                is_written = True

                                for switches in parsed_data.pol_serverfarm_dict[policyname]:
                                    (switch_rule, serverfarm) = switches
                                    counter_inner_rule = 0
                                    
                                    if switch_rule in parsed_data.rule_class_map_dict:
                                        for (rule_type, rule_method, rule_value) in parsed_data.rule_class_map_dict[switch_rule]:
                                            if switch_rule == "class-default":
                                                default_pool_name = virtual_initial_name + "-" + vs_port_name+ "-pool"
                                                is_default_pool = True

                                            else:
                                                pool_name_split = switch_rule.split("-")
                                                if len(pool_name_split) > 1:
                                                    pool_name_init = pool_name_split[1]
                                                else:
                                                    pool_name_init = pool_name_split[0]
                                            irule_pool_name = virtual_initial_name + "-" + pool_name_init + "-pool"
                                            if is_written:  
                                                function.write_irule(rule_type, rule_method, rule_value, irule_pool_name, counter_outer_rule, counter_inner_rule, config_file)
                                                counter_inner_rule += 1
                                    counter_outer_rule += 1

                            elif rule_type == "header" and rule_method == "Host":
                                print ("Irule with HEADER AND HOST METHOD, Please Create")
                            elif rule_type == "source-address":
                                print ("Irule with Source Address Please Create")
                            elif rule_type == "url" and rule_method == "POST":
                                print ("Irule WITH post method Please Create")
                                        
                            #FOR POOL MEMBERS
                            for switches in parsed_data.pol_serverfarm_dict[policyname]:
                                (switch_rule, serverfarm) = switches
                                if switch_rule == "class-default":
                                    default_pool_name = virtual_initial_name + "-" + vs_port_name+ "-pool"
                                    is_default_pool = True
                            
                                else:
                                    pool_name_split = switch_rule.split("-")
                                    if len(pool_name_split) > 1:
                                        pool_name_init = pool_name_split[1]
                                    else:
                                        pool_name_init = pool_name_split[0]
                                        
                                    irule_pool_name =  virtual_initial_name + "-" + pool_name_init + "-pool"

                                if serverfarm in parsed_data.serverferm_details_rserver_dict:
                                    (poolmember_lb_method, poolmember_monitor_name, pool_members) = parsed_data.serverferm_details_rserver_dict[serverfarm]
                                
                                    #Load Balancing Method
                                    load_balancing_mode = function.lb_algorithm_mappings(poolmember_lb_method)

                                    #Monitor Will Refine this later
                                    new_monitor_name = virtual_initial_name + "-" + pool_name_init + "-mon"
                                    monitor_name = function.probe_mappings(poolmember_monitor_name, config_file, parsed_data.probe_dict, new_monitor_name)
                                    print (monitor_name)
                                        
                                    if is_default_pool:    
                                        config_file.write("ltm pool " + default_pool_name + " {\n")
                                        config_file.write("    load-balancing-mode " + load_balancing_mode + "\n")
                                        config_file.write("    members {\n")
                                        for members in pool_members:
                                            (node_name, node_port) = members
                                            (node_port, node_port_name) = function.port_mappings(node_port)

                                            #Remapping the node_port if virtualserver_port is not '0' changing node_port to virtualserver_port
                                            if node_port == '0' and virtualserver_port != '0':
                                                node_port = virtualserver_port
                                                
                                            node_ip = parsed_data.rserver_ip_dict[node_name]
                                            node_name = str(node_name).lower()

                                            config_file.write("        " + node_name + ":" + node_port + " {\n")
                                            config_file.write("            address " + node_ip + "\n")
                                            config_file.write("        }\n")
                                        config_file.write("    }\n")                            
                                        config_file.write("    monitor " + monitor_name + "\n")
                                        config_file.write("    slow-ramp-time 30\n")
                                        config_file.write("}\n")
                                        pool_count += 1
                                    else:
                                        config_file.write("ltm pool " + irule_pool_name + " {\n")
                                        config_file.write("    load-balancing-mode " + load_balancing_mode + "\n")
                                        config_file.write("    members {\n")
                                        for members in pool_members:
                                            (node_name, node_port) = members
                                            (node_port, node_port_name) = function.port_mappings(node_port)
                                            node_ip = parsed_data.rserver_ip_dict[node_name]
                                            node_name = str(node_name).lower()

                                            config_file.write("        " + node_name + ":" + node_port + " {\n")
                                            config_file.write("            address " + node_ip + "\n")
                                            config_file.write("        }\n")
                                        config_file.write("    }\n")                            
                                        config_file.write("    monitor " + monitor_name + "\n")
                                        config_file.write("    slow-ramp-time 30\n")
                                        config_file.write("}\n")
                                        pool_count += 1
                                    
                            
                    if not redirect_url_flag:  
                        #Virtual Server Stuff
                        #SNATPOOL virtualserver_ip_address,virtualserver_protocol,virtualserver_port
                        config_file.write("ltm snat-translation " + virtualserver_ip_address + " {\n")
                        config_file.write("    address " + virtualserver_ip_address + "\n")
                        config_file.write("    inherited-traffic-group true\n")
                        config_file.write("    " + virtualserver_protocol + "-idle-timeout 1800\n")
                        config_file.write("    traffic-group traffic-group-1\n")
                        config_file.write("}\n")
                        config_file.write("ltm snatpool " + virtualserver_ip_address + " {\n")
                        config_file.write("    members {\n")
                        config_file.write("        " + virtualserver_ip_address + "\n")
                        config_file.write("    }\n")
                        config_file.write("}\n")
                   
                        #Virtual Server
                        virtual_servers_all = parsed_data.virtual_ip_proto_port_dict[vip_name]
                        #print (virtual_servers_all)
                        for virtual_details in virtual_servers_all:
                            #print (virtual_details)
                            (virtual_server_ip_address, virtual_server_protocol, virtualserver_port) = virtual_details
                            #Mapping the Ports 
                            (virtualserver_port, vs_port_name)=function.port_mappings(virtualserver_port)

                            virtual_server_name = virtual_initial_name +"-"+vs_port_name+"-vs"
                            if ssl_offload_clientside:
                                ssl_client_profile_name = virtual_initial_name + "-" + "clientssl"
                                print ("ClientSide SSL")
                            if ssl_offload_serverside:
                                ssl_server_profile_name = "serverssl-insecure-compatible"
                                print ("ServerSide SSL")
                            if sticky_virtual:
                                print("Persistence Profile");
                            #print (virtual_server_name)
                            if virtualserver_protocol == "tcp" or virtualserver_protocol == "udp":
                                config_file.write("ltm virtual " + virtual_server_name + " {\n")
                                config_file.write("    destination " + virtual_server_ip_address + ":" + virtualserver_port + "\n")
                                config_file.write("    ip-protocol " + virtualserver_protocol + "\n")
                                config_file.write("    mask " + "255.255.255.255" +"\n")
                                if sticky_virtual:
                                    config_file.write("    persist {\n")
                                    config_file.write("        " + persistence_profile + " {\n")
                                    config_file.write("            default yes\n")
                                    config_file.write("        }\n")
                                    config_file.write("    }\n")
                                if is_default_pool:
                                    config_file.write("    pool " + default_pool_name + "\n")
                                config_file.write("    profiles {\n")
                                if ssl_offload_clientside:
                                    config_file.write("        " + ssl_client_profile_name + " {\n")
                                    config_file.write("            context clientside\n")
                                    config_file.write("        }\n")
                                if ssl_offload_serverside:
                                    config_file.write("        " + ssl_server_profile_name + " {\n")
                                    config_file.write("            context serverside\n")
                                    config_file.write("        }\n")                                
                                if virtualserver_protocol == "tcp":
                                    config_file.write("        tcp-lan-optimized{}\n")
                                else:
                                    config_file.write("        udp{}\n")
                                if sticky_virtual and sticky_type == "http-cookie":
                                    http_profile = True
                                    config_file.write("        http{}\n")
                                    config_file.write("        oneconnect{}\n")
                                if is_irule and not http_profile:
                                    config_file.write("        http{}\n")
                                
                                config_file.write("    }\n")
                                if is_irule:
                                    config_file.write("    rules {\n")
                                    config_file.write("        " + irule_name + "\n")
                                    config_file.write("    }\n")
                                config_file.write("    source-address-translation {\n")
                                config_file.write("        pool " + virtualserver_ip_address + "\n")
                                config_file.write("        type snat\n")
                                config_file.write("    }\n")
                                config_file.write("    vlans {\n")
                                config_file.write("        " + enabled_vlan + "\n")
                                config_file.write("    }\n")
                                config_file.write("    vlans-enabled\n")
                                config_file.write("}\n")
                                virtual_count += 1
                        
                    #For Redirect Virtual Servers 
                    elif redirect_url_flag:

                        redirect_url = redirect_url.replace('\n', '')
                        redirect_url = redirect_url.replace(' ', '')
                        redirect_url = redirect_url.strip()

            
                        virtual_servers_all = parsed_data.virtual_ip_proto_port_dict[vip_name]
                        for virtual_details in virtual_servers_all:
                            (virtual_server_ip_address, virtual_server_protocol, virtualserver_port) = virtual_details
                            (virtualserver_port, vs_port_name)=function.port_mappings(virtualserver_port)
                            (is_domain_lookup, virtual_initial_name) = function.dns_mappings(virtual_server_ip_address)
                            if not is_domain_lookup:
                                virtual_initial_name = vip_name
                            virtual_server_name = virtual_initial_name +"-"+vs_port_name+"-vs"
                            if redirect_url == "https://%h/%p":
                                irule_name = "_sys_https_redirect"
                            else:
                                irule_name = virtual_initial_name + "-redir" + "-irule"
                                redirect_url = redirect_url.split("%p")
                                length_redirect_url = len(redirect_url)
                                redirect_url = redirect_url[0]
                                redirect_url = redirect_url
                                config_file.write("ltm rule " + irule_name + " {\n")
                                config_file.write("    when HTTP_REQUEST {\n")
                                if (length_redirect_url > 1):
                                    config_file.write("        HTTP::respond 302 Location \"" + redirect_url + "[HTTP::uri]" + "\"\n")
                                else:
                                    config_file.write("        HTTP::respond 302 Location \"" + redirect_url+ "\"\n")
                                    
                                config_file.write("    }\n")
                                config_file.write("}\n")
                                

                                

                            config_file.write("ltm virtual " + virtual_server_name + " {\n")
                            config_file.write("    destination " + virtual_server_ip_address + ":" + virtualserver_port + "\n")
                            config_file.write("    ip-protocol " + virtualserver_protocol + "\n")
                            config_file.write("    mask " + "255.255.255.255" +"\n")
                            config_file.write("    profiles {\n")
                            config_file.write("        http{}\n")
                            config_file.write("        tcp-lan-optimized{}\n")
                            config_file.write("    }\n")
                            config_file.write("    rules {\n")
                            config_file.write("        " + irule_name + "\n")
                            config_file.write("    }\n")
                            config_file.write("    vlans {\n")
                            config_file.write("        " + enabled_vlan + "\n")
                            config_file.write("    }\n")
                            config_file.write("    vlans-enabled\n")
                            config_file.write("}\n")
                            virtual_count += 1
                            
                            
                            
                        
            
        print ("Number of Nodes: " + str(node_count))
        print ("Number of Pools: " + str(pool_count))
        print ("Number of Virtuals: " + str(virtual_count))
        config_file.close()
                


