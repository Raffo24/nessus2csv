# @Author : Raffaele Ruggeri
# @Date : 16/11/2023
# @Description : Script per estrarre i dati da un file .nessus in un file csv
# @Repo : nessusToCsv
# @Link : https://github.com/Raffo24/nessus2csv
# @Version : 1
# @License : MIT
################################
# USAGE
# python nessusToCsv.py <file.nessus>
################################
# CONFIGURAZIONE
# --> è possibile configurare i parametri da mostrare nel csv modificando la lista dei campi nel codice python
# --> I campi classici che è possibile aggiungere sono riportati al seguente link https://raw.githubusercontent.com/Raffo24/nessus2csv/main/nessusFields.txt
#     è anche possibile leggere i campi "particolari" disponibili riguardante la singola scansione scommentando le 3 righe di codice relative al debug
###############################
# IMPORTANTE
# L'ordine delle colonne nel csv sarà quello di questa lista

import xmltodict
from lxml import etree
import csv
import sys

severityGrade = {
    "0" : "Info",
    "1" : "Low",
    "2" : "Medium",
    "3" : "High",
    "4" : "Critical"
}

def calcSev(val):
    if val >= 9.0:
        return "Critical"
    elif val >= 7.0:
        return "High"
    elif val >= 5.0:
        return "Medium"
    elif val >= 0.1:
        return "Low"
    else:
        return "Info"

def rec(tree, dic):
    if tree.getchildren() == []:
        dic.setdefault(tree.tag,tree.text.replace("CVSS2#","").replace("CVSS:3.0/",""))
        return
    if tree.tag == "ReportItem":
        dic.setdefault("severity",severityGrade[tree.attrib["severity"]])
        dic.setdefault("port",tree.attrib['port'])
        dic.setdefault("protocol",tree.attrib['protocol'])
        dic.setdefault("service",tree.attrib['svc_name'])
        dic.setdefault("pluginName",tree.attrib['pluginName'])
        dic.setdefault("pluginID",tree.attrib['pluginID'])
        dic.setdefault("pluginFamily",tree.attrib['pluginFamily'])
    for x in tree.getchildren():
        rec(x, dic)

# configura qui i campi che vuoi estrarre
# l'ordine delle colonne nel csv sarà quello di questa lista
campi = [
         "name", 
         "host-ip", 
         "port",
         "severity",
         "operating-system",
         "service",
         "description",
         "solution",
         "cvss_base_score",
         "cvss_vector",
         "cvss3_base_score",
         "cvss3_vector",
         "cwe",
         "cve",
         "exploit_available",
         "metasploit_name",
         "plugin_name",
         "plugin_output",
         "OS-prediction" 
        ]
out = []
n = len(sys.argv)
if n < 2:
    print("Usage: python nessusToCsv.py <file.nessus> \n")
    exit(1)
if sys.argv[1] == "-h" or sys.argv[1] == "--help":
    print("Usage: python nessusToCsv.py <file.nessus> \n")
    exit(1)
# DEBUG debug_var = {}
# riorganizza i dati
i = -1
with open(sys.argv[1], 'rb') as xmlfile:
    root = etree.fromstring(text=xmlfile.read(), parser=etree.XMLParser(huge_tree=True))
    for reportHost in root.getchildren()[1].getchildren():
        hostDict = {}  # dizionario che contiene i dati recuperati di un host dopo l'intera scansione
        hostDict.setdefault("name", reportHost.attrib['name'])
        for child in reportHost[0]:
            hostDict.setdefault(child.get('name') if child.get('name') != "sinfp-ml-prediction" else "OS-prediction",child.text)
        for vuln in reportHost[1:]:
            i += 1
            dicVuln = {} # dizionario che contiene i dati di una determinata vulnerabilità
            rec(vuln, dicVuln)
            out.append({})
            # aggiungi alla vuln i dati dell'host
            dicVuln.update(hostDict)
            # DEBUG debug_var.update(dicVuln)
            # filtra i campi di interesse
            for x in dicVuln.items():
                if x[0] in campi:
                    z = str(x[1])
                    out[i].setdefault(str(x[0]),z if z != "" else "n/a")
            # aggiunge i campi che non sono stati trovati / motivazione --> design del codice
            if "cvss3_base_score" in out[i].keys():
                out[i]["severity"] = calcSev(float(out[i]["cvss3_base_score"]))
            for x in campi:
                if x not in out[i]:
                    out[i].setdefault(x,"n/a")
            
    # DEBUG print(debug_var.keys())
    # write csv in output
    file_out = open(sys.argv[1][:-7] + ".csv", 'w', encoding='utf-8', newline='')
    csv_writer = csv.writer(file_out, delimiter =';')
    csv_writer.writerow(campi)
    # sort dict "out" by key
    for scan in out:
        csv_writer.writerow([s.encode('unicode_escape').decode() for s in dict(sorted(scan.items(), key = lambda x : campi.index(x[0]))).values()])
    file_out.close()
    print(f"File {sys.argv[1][:-7]}.csv creato con successo!")
