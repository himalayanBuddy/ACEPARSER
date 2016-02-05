#This work is from Harish Pokharel
import re
import sys
import socket

#open file
filename = sys.argv[1]
f = open(filename, 'r')

#default values
default_predictor = "round-robin"
default_probe = "tcp"
default_icmp_probe = "gateway_icmp"

#Initialize Variables
probe_type = ""
probe_name = ""
probe_port = ""
probe_method = ""
probe_url = ""
probe_status = ""
probe_regex = ""
probe_host = ""


#list parameters
virtual_name = []
virtual_name_ip_list = []
virtual_ip_proto_port_list = []
pol_serverfarm_list = []
sticky_serverfarm_list = []
redirect_serverfarm_list = []
serverfarm_host_list = []
temp_serverfarm_host_list = []
temp_serverfarm_rserver_host_list = []
redirect_host_list = []
serverfarm_rserver_list = []
rserver_ip_list = []
serverfarm_class_list = []
serverfarm_pol_class_farm_tuple = ()
serverfarm_pol_class_farm_tuple_list = []
rule_class_map_list = []
temp_tuple_list = []
temp_pol_class_farm_tuple_list = []
ssl_virtual_name = []
ssl_policy_name = []
rserver_name_list = []

#Irules
http_irule_list = []
irule_value_list = []

#dictionary parameter

virtual_lbpolicy = {}
virtual_ip_proto_port_dict = {} 
pol_serverfarm_dict = {}
sticky_serverfarm_dict = {}
redirect_serverfarm_dict = {}
serverferm_details_rserver_dict = {}
rserver_ip_dict = {}
redirect_host_dict = {}
rule_class_map_dict = {}
ssl_client_virtual_dict = {}
ssl_server_virtual_dict = {}
probe_dict = {}

#Define Patterns

pattern_virtual = 'class (.*)'
pattern_ssl_proxy_server = 'ssl-proxy (server) .*'
pattern_ssl_proxy_client = 'ssl-proxy (client) .*'
pattern_lb_policy = 'loadbalance policy (.*)'
pattern_virtual_name_ip_port = 'class-map match.* (.*)'
#pattern_virtual_ip_proto_port = 'match virtual-address (\d+\.\d+\.\d+\.\d+)\s?(\w+)? eq (\d+|\w+)'
pattern_virtual_ip_proto_port ='match virtual-address (\d+\.\d+\.\d+\.\d+)\s?(\w+)? (?:eq\s+)?(\d+|\w+)'
pattern_pol_serverfarm = 'policy-map type loadbalance first-match (.*)'
pattern_serverfarm_pol = 'serverfarm (.*)'
pattern_sticky_ip_serverfarm = '(sticky) (.*\s)255.255.255.255 address (source) (.*)'
pattern_sticky_other_serverfarm = '(sticky) (.*?\s)(.*?\s)(.*)'
pattern_redirect_serverfarm = 'serverfarm redirect (.*)'
pattern_rserver_redirect = 'rserver redirect (.*)'
pattern_redirection_type = 'webhost-redirection (.*)'
pattern_host_serverfarm = 'serverfarm host (.*)'
pattern_serverfarm_predictor = 'predictor (\w+)'
pattern_serverfarm_probe = 'probe (.*)'
#pattern_serverfarm_rserver = 'rserver ([^host\s].*?)\s+(\d+)?'
pattern_serverfarm_rserver = 'rserver(?!\shost) (.*?)\s(\d+|w+)?'
pattern_rserver_ip = 'rserver host (.*)'
pattern_ip_address = 'ip address (\d+\.\d+\.\d+\.\d+)'

#IRULE CLASS_MAP PATTERNS
pattern_rule_class_map = 'class-map type http loadbalance match.* (.*)'
#pattern_rule_url = 'match (http) (url) \/(.*?)\/'
pattern_rule_url = 'match (http) (url) \/(\w+)'
pattern_rule_source = 'match (source-address) (\d+.\d+.\d+.\d+) (\d+.\d+.\d+.\d+)'
pattern_rule_http_header = 'match http (header) (\w+) header-value (.*)'
pattern_rule_http_method = 'match http (url) \.\*\/(.*) method (\w+)'

#Flags 

sticky_flag = False
rserver_flag = False
redirect_serverfarm_match_flag = False
serverfarm_rserver_match_flag = False
serverfarm_class_match_flag = False
no_probe_flag = False

#
rule_type = ''
rule_method = ''
value = ''

#

#Remove NewLines
def remove_newline (data):
    return (data.replace('\n', ''))

for line in f:
    #line = line.strip()
    #Setting the Flags
    virtual = False
    virtual_name_ip = False
    virtual_ip_proto_port_flag = False
    pol_serverfarm_flag = False
    value_match_flag = False
    
 
    virtual_match = re.findall(pattern_virtual, line)
    if virtual_match:
        virtual = True
        virtual_name = []
        virtual_name.append(virtual_match[0])
    if len(virtual_name) == 1:
        lb_policy = re.findall(pattern_lb_policy, line)
        if lb_policy:
            if virtual_name[0] not in virtual_lbpolicy:
                virtual_lbpolicy[virtual_name[0]] =  lb_policy[0]
            virtual_name = []

    #Added for SSL Offload
    virtual_name_ssl_offload_match = re.findall(pattern_virtual, line)
    if virtual_name_ssl_offload_match:
        ssl_virtual_name = []
        ssl_virtual_name.append(virtual_name_ssl_offload_match[0])
    if len(ssl_virtual_name) == 1:
        ssl_server_match =  re.findall(pattern_ssl_proxy_server, line)
        if ssl_server_match:
            if ssl_virtual_name[0] not in ssl_client_virtual_dict:
                ssl_client_virtual_dict[ssl_virtual_name[0]] = ssl_server_match[0]
            ssl_virtual_name = []

    #If ServerSide SSL is required
    policy_name_ssl_offload_serverside_match = re.findall(pattern_pol_serverfarm, line)
    if policy_name_ssl_offload_serverside_match:
        ssl_policy_name = []
        ssl_policy_name.append(policy_name_ssl_offload_serverside_match[0])
    if len(ssl_policy_name) == 1:
        ssl_client_match = re.findall(pattern_ssl_proxy_client, line)
        if ssl_client_match:
            if ssl_policy_name[0] not in ssl_server_virtual_dict:
                ssl_server_virtual_dict[ssl_policy_name[0]] = ssl_client_match[0]
            ssl_policy_name = []
        
        
        


    #Get Virtual IP, PORT AND PROTOCOL
    virtual_name_ip_match = re.findall(pattern_virtual_name_ip_port, line)
    if virtual_name_ip_match:
        virtual_name_ip = True
        virtual_name_ip_list = []
        virtual_name_ip_list.append(virtual_name_ip_match[0])
    if len(virtual_name_ip_list) == 1:
        virtual_ip_proto_port = re.findall(pattern_virtual_ip_proto_port, line)
        if virtual_ip_proto_port:
            virtual_ip_proto_port_flag = True
            if virtual_ip_proto_port_flag:
               virtual_ip_proto_port_list.append((virtual_ip_proto_port,virtual_name_ip_list))
                                                 
     
        if len(virtual_ip_proto_port_list) > 0 and virtual_ip_proto_port_flag == False:
            final_ip_proto_port = []
            for ip_name in virtual_ip_proto_port_list:
                (ip_proto_port, vs_name) = ip_name
                final_ip_proto_port.append(ip_proto_port[0])

                
            if vs_name[0] not in virtual_ip_proto_port_dict:
                    virtual_ip_proto_port_dict[vs_name[0]] = final_ip_proto_port
                    final_ip_proto_port = []
                    
            
            virtual_ip_proto_port_list = []
                    
     

    #Get the Serverfarm AND POLICY Details
    pol_serverfarm_match = re.findall(pattern_pol_serverfarm, line)
    
    if pol_serverfarm_match:
        pol_serverfarm_list = []
        pol_serverfarm_list.append(pol_serverfarm_match[0])
    if len(pol_serverfarm_list) == 1:
        ##IRULE CREATION PATTERN
        serverfarm_class_match = re.findall(pattern_virtual, line)
        if serverfarm_class_match:
            serverfarm_class_list = []
            serverfarm_class_list.append(serverfarm_class_match[0])
        if len(serverfarm_class_list) == 1:
            serverfarm_pol_match = re.findall(pattern_serverfarm_pol, line)
            if serverfarm_pol_match:
                serverfarm_pol_class_farm_tuple_list.append([(serverfarm_class_list[0],serverfarm_pol_match[0])])
                if pol_serverfarm_list[0] in pol_serverfarm_dict:
                    pol_serverfarm_dict[pol_serverfarm_list[0]].append(serverfarm_pol_class_farm_tuple_list[0][0])
                else:
                    pol_serverfarm_dict[pol_serverfarm_list[0]] = serverfarm_pol_class_farm_tuple_list[0]
                   
                    
                serverfarm_pol_class_farm_tuple_list = []
                serverfarm_pol_class_farm_tuple = ()
            

    #Find Out the Sticky Serverfarm
    sticky_serverfarm_match = re.findall(pattern_sticky_ip_serverfarm, line)
    if sticky_serverfarm_match:
        sticky_serverfarm_list.append(sticky_serverfarm_match[0])
        sticky_flag = True
    else:
        sticky_serverfarm_match = re.findall(pattern_sticky_other_serverfarm, line)
        if sticky_serverfarm_match:
            sticky_serverfarm_list.append(sticky_serverfarm_match[0])
            sticky_flag = True        

    if sticky_flag:
        sticky_serverfarm = re.findall(pattern_serverfarm_pol, line)
        if sticky_serverfarm: 
            sticky_serverfarm_dict[sticky_serverfarm_list[0][3]] = [sticky_serverfarm_list[0][0],sticky_serverfarm_list[0][1],sticky_serverfarm_list[0][2],sticky_serverfarm[0]]
            sticky_serverfarm_list = [] 
            sticky_flag = False


    #Find the Redirect Serverfarm
    redirect_serverfarm_match = re.findall(pattern_redirect_serverfarm, line)
    if redirect_serverfarm_match:
        redirect_serverfarm_list.append(redirect_serverfarm_match[0])
        redirect_serverfarm_match_flag = True 

   #FIND SERVERFARM AND RSERVERS
    if len(serverfarm_host_list) == 2:
        serverfarm_probe_match = re.findall(pattern_serverfarm_probe, line)
        if serverfarm_probe_match:
            serverfarm_host_list.append(serverfarm_probe_match[0])
        else:
            serverfarm_host_list.append(default_probe)
    if len(serverfarm_host_list) == 1:
        serverfarm_predictor_match = re.findall(pattern_serverfarm_predictor, line)
        if serverfarm_predictor_match:
            serverfarm_host_list.append(serverfarm_predictor_match[0])
        else:
            serverfarm_host_list.append(default_predictor)
            serverfarm_probe_match = re.findall(pattern_serverfarm_probe, line)
            if serverfarm_probe_match:
                serverfarm_host_list.append(serverfarm_probe_match[0])
            else:
                serverfarm_host_list.append(default_probe)
                
        
    serverfarm_host_match = re.findall(pattern_host_serverfarm, line)

    if serverfarm_host_match:
        serverfarm_host_list = []
        serverfarm_host_list.append(serverfarm_host_match[0])


        
    if len(serverfarm_host_list) > 2:
        temp_serverfarm_host_list.append((serverfarm_host_list[0],serverfarm_host_list[1],serverfarm_host_list[2]))
        serverfarm_host_list = []

    if len(temp_serverfarm_host_list) > 0:
        serverfarm_rserver_match = re.findall(pattern_serverfarm_rserver, line)
        if serverfarm_rserver_match:
            temp_serverfarm_rserver_host_list.append(serverfarm_rserver_match[0])
        elif serverfarm_host_match or line.isspace() or redirect_serverfarm_match:
            if temp_serverfarm_host_list[0][0] not in serverferm_details_rserver_dict:
                serverferm_details_rserver_dict[temp_serverfarm_host_list[0][0]] = (temp_serverfarm_host_list[0][1],temp_serverfarm_host_list[0][2],temp_serverfarm_rserver_host_list)
                
            temp_serverfarm_rserver_host_list = []
            temp_serverfarm_host_list = []
                                         
    

    ###THIS HAS NOT BEEN YET VERIFIED

    if redirect_serverfarm_match_flag:  
         serverfarm_redirect_rserver_match = re.findall(pattern_serverfarm_rserver, line)
         if serverfarm_redirect_rserver_match:
             if len(redirect_serverfarm_list) == 1:
                 redirect_serverfarm_dict[redirect_serverfarm_list[0]] = serverfarm_redirect_rserver_match[0]
                 redirect_serverfarm_list = []
                 redirect_serverfarm_match_flag = False
             
         

    #GET THE RSERVER DETAILS
    #if not rserver_flag:

    if len(rserver_name_list) == 1:
        rserver_ip_address_match = re.findall(pattern_ip_address, line)
        if rserver_ip_address_match:
            if rserver_name_list[0] not in rserver_ip_dict:
                rserver_ip_dict[rserver_name_list[0]] = rserver_ip_address_match[0]
            rserver_name_list = []
        else:
            if rserver_ip_match[0] not in rserver_ip_dict:
               rserver_ip_dict[rserver_ip_match[0]] = '0.0.0.0'
            rserver_name_list = []
    rserver_ip_match = re.findall(pattern_rserver_ip, line)
        

    if rserver_ip_match:
        rserver_name_list = []
        rserver_name_list.append(rserver_ip_match[0])

   #GET REDIRECT RSERVER DETAILS
    redirect_host_match = re.findall(pattern_rserver_redirect, line)
    if redirect_host_match:
        redirect_host_list.append(redirect_host_match[0])
   
    if len(redirect_host_list) == 1:
        redirect_type_match = re.findall(pattern_redirection_type, line)
        if redirect_type_match:
            redirect_host_dict[redirect_host_list[0]] = redirect_type_match[0]
            redirect_host_list = []
     ############## NOT VERIFIED END ##################

    #MATCHING FOR IRULES
    
    http_irule_match = re.findall(pattern_rule_class_map,line)
    other_irule_match = re.findall(pattern_virtual_name_ip_port, line)
    if http_irule_match:
        http_irule_list = []
        http_irule_list.append(http_irule_match[0])
    elif other_irule_match:
        http_irule_list = []
        http_irule_list.append(other_irule_match[0])
        
    if len(http_irule_list) == 1:
        http_irule_url_match = re.findall(pattern_rule_url, line)
        http_irule_source_match = re.findall(pattern_rule_source, line)
        http_irule_header_match = re.findall(pattern_rule_http_header, line)
        http_irule_method_match = re.findall(pattern_rule_http_method, line)
        if http_irule_url_match:
            value_match_flag = True
            irule_value_list.append((http_irule_url_match,http_irule_list))
        elif http_irule_source_match:
            value_match_flag = True
            irule_value_list.append((http_irule_source_match,http_irule_list))
        elif http_irule_header_match:
            value_match_flag = True
            irule_value_list.append((http_irule_header_match,http_irule_list))
        elif http_irule_method_match:
            value_match_flag = True
            (method_type, method_value, method_name) = http_irule_method_match[0]
            http_irule_method_match = [(method_type, method_name, method_value)]
            irule_value_list.append((http_irule_method_match,http_irule_list))
                                       


    if len(irule_value_list) > 0 and value_match_flag == False:
        final_irule_value_list = []
        for (irule_values,irules_name) in irule_value_list:
            final_irule_value_list.append(irule_values[0])
        if irules_name[0] not in rule_class_map_dict:
            rule_class_map_dict[irules_name[0]] = final_irule_value_list
            
        irule_value_list = []

    
    #PROBE
    split_data = line.split(' ')
    if len(split_data) > 2:
        if split_data[0] == "probe":
            #Clear Everything when new probe is found
            probe_type = ""
            probe_name = ""
            probe_port = ""
            probe_method = ""
            probe_url = ""
            probe_status = ""
            probe_regex = ""
            probe_host = ""
            
            probe_type = remove_newline(split_data[1])
            probe_name = remove_newline(split_data[2])

        
        elif split_data[2] == "port":
            probe_port = remove_newline(split_data[3])
        elif split_data[2] == "request":
            probe_method = remove_newline(split_data[4])
            probe_url = remove_newline(split_data[6])
        elif split_data[2] == "expect":
            if split_data[3] == "status":
                probe_status = remove_newline(split_data[4])
            elif split_data[3] == "regex":
                probe_regex = remove_newline(split_data[4])
        elif split_data[2] == "header":
            if split_data[3] == "Host":
                probe_host = remove_newline(split_data[5])

        if probe_name != '':
            probe_dict[probe_name] = (probe_type, probe_port, probe_method, probe_url, probe_status, probe_regex, probe_host)



            
            
            
#f.close()                 
#print (virtual_lbpolicy)
#print (virtual_ip_proto_port_dict)
#print (pol_serverfarm_dict)
#print (sticky_serverfarm_dict)
#print (serverferm_details_rserver_dict)
#print (rserver_ip_dict)
#print (redirect_serverfarm_dict)
#print (redirect_host_dict)
#print (rule_class_map_dict)
#print (ssl_client_virtual_dict)
#print (ssl_server_virtual_dict)
#print (probe_dict)
 
