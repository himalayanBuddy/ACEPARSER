import socket
#Port Mappings
def port_mappings(port):
    port = str(port)
    if port == '':
        mapped_port = '0'
        mapped_port_name = 'any'
    elif port == 'www':
        mapped_port = '80'
        mapped_port_name = 'http'
    elif port == 'https':
        mapped_port = '443'
        mapped_port_name = 'https'
    else:
        mapped_port = port
        mapped_port_name = port
    return (mapped_port, mapped_port_name)

#DNS Mappings
def dns_mappings(ip_address):
    try:
        domain_lookup = True
        domain_name = socket.gethostbyaddr(ip_address)
        domain_split = domain_name[0].split('.')
        init_name = domain_split[0]
    except:
        domain_lookup = False
        init_name = None
    return (domain_lookup, init_name)
#LB algorithm Mappings
def lb_algorithm_mappings(ace_lb_method):
    if ace_lb_method == "leastconns":
        lb_method = "least-connections-member"
    else:
        lb_method = "round-robin"       
    return(lb_method)

#Write Rules
def write_irule(rule_type, rule_method, rule_value, irule_pool_name, counter_outer_irule, counter_inner_irule, file_handle):
    if rule_type == "http" and rule_method == "url":
        #config_file = open(path_to_virtual_file, 'a')
        if counter_outer_irule == 0 and counter_inner_irule == 0:
            file_handle.write("            if {$uri equals \"/"+ rule_value.lower() +"\"} {\n")
            file_handle.write("                pool " + irule_pool_name + "\n")
            file_handle.write("            }\n")
        else:
            file_handle.write("            elseif {$uri equals \"/"+ rule_value.lower() +"\"} {\n")
            file_handle.write("                pool " + irule_pool_name + "\n")
            file_handle.write("            }\n")
    

#Persistence Profile Mappings

def persistence_mappings(sticky_type, sticky_value):
    sticky_type = sticky_type.replace(' ', '')
    sticky_type = sticky_type.replace('\n', '')
    sticky_type = sticky_type.rstrip()

                            
    sticky_value = sticky_value.replace(' ', '')
    sticky_value = sticky_value.replace('\n', '')
    sticky_value = sticky_value.rstrip()

    if sticky_type == "ip-netmask" and sticky_value == "source":
        persistence_profile = "source_addr"
    elif sticky_type == "http-cookie" and sticky_value.lower() == "jsessionid":
        persistence_profile = "JSESSIONID"
    elif sticky_type == "http-cookie":
        persistence_profile = "cookie"
    else:
        persistence_profile = "source_addr"
    return (persistence_profile, sticky_type)




#Monitor Mappings

def probe_mappings(poolmember_monitor_name, config_file, dictionary, new_monitor_name):
    if poolmember_monitor_name in dictionary:
        (probe_type, probe_port, probe_method, probe_url, probe_status, probe_regex, probe_host) = dictionary[poolmember_monitor_name]
        if probe_type == "http" or probe_type == "https":
            config_file.write("ltm monitor " + probe_type + " " + new_monitor_name +" {\n")
            config_file.write("    defaults-from "+ probe_type + "\n")                
            if probe_port != '':
                config_file.write("    destination *:" + probe_port + "\n")
            else:
                config_file.write("    destination *:*\n")
            config_file.write("    interval " + "10" + "\n")
            if probe_regex != '':
                config_file.write("    recv " + probe_regex + "\n")
            else:
                if probe_status != '':
                    config_file.write("    recv " + "\"HTTP/1\\.(0|1) (2|3)\"\n")

            if probe_host == '':
                probe_host = "localhost"
            probe_method = probe_method.upper()
            if probe_url != '':
                config_file.write("    send " + "\"" + probe_method + " " + probe_url + " HTTP/1.1\\r\\nHost: " + probe_host + "\\r\\nConnection: Close\\r\\n\\r\\n\n")
            else:
                config_file.write("    send " + "\"" + "GET" + " " + "\/" + " HTTP/1.1\\r\\nHost: " + probe_host + "\\r\\nConnection: Close\\r\\n\\r\\n\n")
            config_file.write("    time-until-up 0\n")
            config_file.write("    timeout 31\n")
            config_file.write("}\n")

        elif probe_type == "tcp" and probe_port !="":
            config_file.write("ltm monitor tcp " + new_monitor_name +"{\n")
            config_file.write("    defaults-from tcp\n")
            config_file.write("    destination *:" + probe_port +"\n")
            config_file.write("    interval " + "10" + "\n")
            config_file.write("    time-until-up 0\n")
            config_file.write("    timeout 31\n")
            config_file.write("}\n")

        elif probe_type == "tcp" and probe_port =="":
            new_monitor_name = "tcp"

        else:
            new_monitor_name = "gateway-icmp"
            
                    
                
    else:
        new_monitor_name = "gateway-icmp"

    return (new_monitor_name)
        

    
