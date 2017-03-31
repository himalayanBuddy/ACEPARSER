# Introduction

This script is developed to parse ACE configuration and convert it to equivalent F5 BIG-IP LTM configuration.
It is developed using Python 3. But runs great in Python 2. If any errors running on python 2.x please let me know. 
This script has helped me lot and saved lots of time migrating ACE configurations to F5 LTM.

This script has been tailored reading the ACE configurations that we had. But it should basically work on most of all ACE configurations.

# Documentation

This script contains 3 files.

1. ace2f5parser.py - script parsing the ACE configs
2. create_f5_configs.py - ace2f5parser.py creates equivalent F5 BIG-IP LTM configuration and saves to file.
3. parser_functions.py - Related functions and implementations

# Usage

1.Save all the ACE configs in a text file. 

On ACE
```
#sh run
```
Save the output to a text file. eg. all_ace_configs.txt

2.Create a text file containing the name of the VIPs that needs to be migrated. If you have ANM you can all dump the VIP names to a single xls file and choose vips from there to save the names in a text file. The names fo the vip in the text file should be exact that you have in the ace configs file created in step 1 "all_ace_configs.txt"

Eg. "first_batch_migrate_vip.txt" should contain the vip names. If you have vip names as vip1_a, vip2_a, vip3_a then file should have as below separeated by newlines.
```
vip1_a
vip2_a
vip3_a  
```

3.Create a folder named "F5Configs" with read/write access on the location where you are running the script. To change the location you need to modify "create_f5_configs.py" script.

4.Run the script as:
```
python create_f5_configs.py \<ACECONFIGSFILE\> \<VIPNAMESFILE\>
```
Eg.
we had created two files above:
ACECONFIGSFILE as: all_ace_configs.txt
VIPNAMESFILE as: first_batch_migrate_vip.txt

So, Run the code as:
```
python create_f5_configs.py all_ace_configs.txt first_batch_migrate_vip.txt
```
5.All F5 BIG-IP LTM configs will be generated inside F5Configs folder per vip. Nodes are written in a single file.
```
Eg: In our case the files generated in F5Configs folder will have LTM configs with below similar file name 
vip1_a.txt 
vip2_a.txt 
vip3_a.txt
AND One more file for all nodes. all_nodes_file.txt
```
6.The sript will first do the DNS lookup for the VIP IP so that it can give the VIP equivalent name. If Domain Name is retrieved by the script, It will use the first part separated by dots. So, if domain name is "zzz.example.com". The virtual server name will start with "zzz".If it's http virtual server then, full virtual server name will be "zzz-http-vs", similarly pool name will be "zzz-http-pool".If it is unable to retrieve the domain name will use the existing VIP name in the ACE config.


7.The configs are in bigip.conf style. I have found the following procedure best for me while importing the configs to F5 LTM.
```
a)First I scrutinized the generated text config file. If needed made modifications as required and saved the file. 

b)Created a Folder in /shared/tmp or /var/tmp on F5 BIG-IP LTM device where the configs needed to be migrated.
eg: /var/tmp/First_Batch_F5Configs

c)Uploaded the F5 config flies to the folder created in step b.
eg: After scrutinization on step a "/var/tmp/First_Batch_F5Configs" has:
vip1_a.txt 
vip2_a.txt 
vip3_a.txt
all_nodes_file.txt

d)Verified the files to check if the configuration is ok to merge and load.
eg:
  (tmsh)# load sys config file /var/tmp/First_Batch_F5Configs/all_nodes_file.txt merge verify
  (tmsh)# load sys config file /var/tmp/First_Batch_F5Configs/vip1_a.txt merge verify
   
 e)If it fails with errors, fix the errors and repeated step d.
 
 f)If it succeeds without errors, merged the file to BIGIP LTM config as:
   (tmsh)# load sys config file /var/tmp/First_Batch_F5Configs/all_nodes_file.txt merge
   (tmsh)# load sys config file /var/tmp/First_Batch_F5Configs/vip1_a.txt merge
   
 g)Saved the config:
     eg:
     (tmsh)# save sys config
     
 h)Synced the config
     eg:
     (tmsh)# run cm config-sync to-group MY_FAILOVER_GROUP 
 ```
 # Notes
 
 a) The SNATPOOL created uses the vip IP. If you want to use any other IPs or automap, please change the script or modify F5 Config   files generated.
 
 b) The VIP is enabled on certain VLAN. Please check create_f5_configs.py and point it to appropriate vlan. enabled_vlan = "VlanXXX". Currently this script allows only one Vlan. If you want to remove please modify the script or delete it from F5 Configs file that gets generated.
 
