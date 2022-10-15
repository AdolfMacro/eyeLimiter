from scapy.all import *
from os import system
from re import findall
from sys import argv
from colorama import Fore
from os import getcwd
from os.path import isfile
import yaml
def main():
    def chARG(confFile):
        helpS=f"""
-c OR --config-file -> Config file path (default : {confFile})
-h OR --help        -> This menu ...
        """
        tArgv=["--config-file" , "-c" , "--help" , "-h"]
        for i in range(1,len(argv),2):
            if argv[i] in tArgv:
                if argv[i]=="--config-file" or argv[i] == "-c":
                    if isfile(argv[i+1]) :
                        confFile=argv[i+1]
                    else :
                        print(f"{Fore.LIGHTRED_EX}\n[*] Error : File {argv[i+1]} not found !{Fore.RESET}")        
                else :
                    print(helpS)

            else:
                print(f"{Fore.LIGHTRED_EX}\n[*] Error : {argv[i]} Not define !{Fore.RESET}\n{helpS}")
        return confFile
    def readConfig(confFile):
        with open(confFile , 'r') as config:
            cfg = yaml.safe_load(config)
        return cfg
    def mainHandler(cfg):
        ipLogsDownload={}
        ipLogsUpload={}
        def handler(packet):
            if IP in packet:
                if packet[IP].dst in cfg["vipUsers"] or cfg["vipUsers"]==".":
                    limitDownload=cfg["usersLimit"]["download"]["vipUsers"]/21
                elif packet[IP].dst in cfg["sUsers"] or cfg["sUsers"]==".":
                    limitDownload=cfg["usersLimit"]["download"]["sUsers"]/21
                else :
                    limitDownload=cfg["usersLimit"]["download"]["nUsers"]/21
                if packet[IP].dst in ipLogsDownload.keys():
                    if ipLogsDownload[packet[IP].dst]+len(packet)/1048576 > limitDownload:
                        if limitDownload:
                            print(f"{Fore.LIGHTRED_EX}Up to {(limitDownload*21)/1024} download : {packet[IP].dst}{Fore.RESET}")
                    else:
                        ipLogsDownload.update({packet[IP].dst : ipLogsDownload[packet[IP].dst]+len(packet)/1048576 })
                else :
                    ipLogsDownload.update({packet[IP].dst : len(packet)/1048576 })
                if packet[IP].dst in cfg["vipUsers"] or cfg["vipUsers"]==".":
                    limitUpload=cfg["usersLimit"]["upload"]["vipUsers"]/21
                elif packet[IP].dst in cfg["sUsers"] or cfg["sUsers"]==".":
                    limitUpload=cfg["usersLimit"]["upload"]["sUsers"]/21
                else :
                    limitUpload=cfg["usersLimit"]["upload"]["nUsers"]/21
                if packet[IP].src in ipLogsUpload.keys():
                    if ipLogsUpload[packet[IP].src]+len(packet)/1048576 > limitUpload:
                        print(f"{Fore.LIGHTRED_EX}Up to {(limitUpload*21)/1024} upload : {packet[IP].src}{Fore.RESET}")
                    else:
                        ipLogsUpload.update({packet[IP].src : ipLogsUpload[packet[IP].src]+len(packet)/1048576 })
                else :
                    ipLogsUpload.update({packet[IP].src : len(packet)/1048576 })
        sniff(iface=cfg["iface"] , prn=handler , store=False )
    confFile=chARG(getcwd()+"/config/config.yaml")
    cfg=readConfig(confFile)
    mainHandler(cfg)
if __name__=="__main__":
    try:
        main()
    except PermissionError:
        print(f"{Fore.LIGHTRED_EX}[*] Error : run tool as {Fore.LIGHTGREEN_EX}root {Fore.LIGHTRED_EX}!{Fore.RESET}")
