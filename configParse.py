import OpenSSL , ssl,  argparse ,json, os.path, validators, requests # , objectpath
from datetime import datetime
from dateutil.parser import parse
from urllib.parse import urljoin
from akamai.edgegrid import EdgeGridAuth
#from urllib.parse import urljoin
from akamai.edgegrid import EdgeGridAuth
from pathlib import Path

parser = argparse.ArgumentParser(description='Akamai Cert Validity Automation Script')
parser.add_argument('-d', nargs='+', type=str, help='<Required> List of domains to query.',
                    required=False)
parser.add_argument('-o', type=str, help='-o JSON for json formated output',
                    required=False)
parser.add_argument('-t', type=str, choices=['LIST','PM'], help='File Type (LIST, PM)',
                    required=False)
parser.add_argument('-f', type=str, help='File with list of domains (one per line)',
                    required=False)               
parser.add_argument('-v', help='Show Errors',
                    required=False, action='store_true')
args = vars(parser.parse_args())



class Credentials:
    def __init__(self):
        self.client_secret = ""
        self.host = ""
        self.access_token = ""
        self.client_token = ""

def readFile(File,Ftype:str,outtype: str,verbose:str):
    
    if Ftype != "API":
        if os.path.exists(File):
            if Ftype == "List":
                lines = [line.rstrip('\n') for line in open(File)]
                getCertificates(lines,outtype,verbose)
            else:
                #print(f)
                try:
                    with open(File) as handle:
                        dictdump = json.loads(handle.read())

                    
                except:
                    parser.error("Unable to Parse JSON File, please validate format.")
                else:
                    origins=[]
                    finditem(dictdump,origins)
                    print(origins)
                    getCertificates(origins,outtype,verbose)
        else:
            parser.error("The File {} does not exist!".format(File))
     
    else:
        origins=[]
        finditem(File,origins)
        print(origins)

        getCertificates(origins,outtype,verbose)


                



def finditem(obj,origins:list):

    for ok, ov in obj.items(): 
        if ok == "name" and ov == "origin":
            options = dict(obj["options"])
            if options["originType"] != "NET_STORAGE":
                origins.append (dict(obj["options"])["hostname"])
    for k, v in obj.items():
        if isinstance(v,dict) or isinstance(v,list):
            if "values" not in k.lower():
                if isinstance(v,list):
                    if len(v) > 0:
                        for i in v:
                            if isinstance(i, dict):
                                finditem(dict(i),origins)
                else:
                    finditem(v,origins)

def printJson(output):

    print(json.dumps(output, indent=4, sort_keys=True))
    
    return
def getCertificates(domains: list,outtype: str,verbose:str):
    errors=[]
    
    items = {}
    
    item_list= []
        
    for host in domains:
       
        if "{{" in host:
            if verbose:
                errors.append("'{}' is a variable and will not be looked up!".format(host))
        else:
            if validators.domain(host) != True:
                if verbose:
                    errors.append("'{}' is not a valid domain!".format(host))
                
                continue
            try:
                hostname = host
                port = 443
                conn = ssl.create_connection((hostname, port))
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sock = context.wrap_socket(conn, server_hostname=hostname)
                certificate = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,certificate)
            except:
                if verbose:
                    errors.append("Unable to connect to '{}'!".format(host))
                continue
            else:
                serial= '{0:x}'.format(x509.get_serial_number())
                #print(serial)
                exp_date = str(x509.get_notAfter().decode('utf-8'))
                dt = parse(exp_date)

                daystoexp=dt.replace(tzinfo=None)-datetime.utcnow()

                if outtype == "JSON":
                    item = {}
                    item['Domain'] = str(host)
                    item['Serial'] = str(serial)
                    item['ExpDate'] =  str(dt.date())
                    item['DaysLeft']  =  daystoexp.days
                    json_data = json.dumps(item)
                    item_list.append(json_data)
                else:
                    print("SSL Certificate for {}, will be expire on (DD-MM-YYYY): {}, {} days from now.".format(host, dt.date(),daystoexp.days))   

    if outtype == "JSON":
        
        items['Certificates'] = item_list
        if verbose:
            items['Errors'] = errors
        printJson(items)
    else:
        if verbose:
            print("The Following Errors Occured: {}".format(errors))
    return

def readEdgeRC():
    a = Credentials()
    home = str(Path.home())
    edgerc = '/.edgerc'
    if os.path.exists(home+edgerc):
        with open(home+edgerc) as fp:
            selectedProfile=False
            line = fp.readline()
            while line:
                line = fp.readline()
                if line.strip().lower() == "[papi]":
                    selectedProfile=True
                if line.strip() == "":
                    selectedProfile=False
                if selectedProfile == True and line.strip().lower() != "[papi]":
                    key,value=line.split(" = ")
         
                    if key== "client_secret":
                        a.client_secret=value.rstrip()
                    elif key== "host":
                        a.host=value.rstrip()
                    elif key== "access_token":
                        a.access_token=value.rstrip()
                    elif key== "client_token":
                        a.client_token=value.rstrip()
                if a.client_token != "" and a.host != "" and a.client_secret != "" and a.access_token != "":
                    fp.close()
                    return a
        fp.close()
        return None
    else:
        parser.error("The File {} does not exist!".format(home+edgerc))

def papi(a: Credentials,action:str,verbose:str):
    http = requests.Session()
    http.auth= EdgeGridAuth(
            client_token=a.client_token,
            client_secret=a.client_secret,
            access_token=a.access_token
        )
    validActions = ["ListGroups","ListContracts","ListProperties","GetRuleTree"]
    if action not in validActions:
        return "Error"
    elif action == validActions[0]:
        endpoint='/papi/v1/groups'
        
        result = http.get(urljoin("https://" + a.host + "/", endpoint))
        http.close()
        return json.loads(json.dumps(result.json()))

    elif action == validActions[2]:
        groups=papi(a,"ListGroups",verbose)
        group = groups['groups']['items'][0]['groupId']
        contract=groups['groups']['items'][0]['contractIds'][0]
        endpoint= '/papi/v1/properties?contractId={}&groupId={}'.format(contract,group)
        result = http.get(urljoin("https://" + a.host + "/", endpoint))
        http.close()
        return json.loads(json.dumps(result.json()))
    elif action == validActions[3]:
        p = papi(a,"ListProperties",verbose)
        
        endpoint= "/papi/v1/properties/{}/versions/{}/rules?contractId={}&groupId={}&validateRules=true&validateMode=fast".format(
            p['properties']['items'][0]['propertyId'],
            p['properties']['items'][0]['latestVersion'],
            p['properties']['items'][0]['contractId'],
            p['properties']['items'][0]['groupId']
        )
        result = http.get(urljoin("https://" + a.host + "/", endpoint))
        http.close()
        readFile(json.loads(json.dumps(result.json())) ,"API","",verbose)
        #return json.loads(json.dumps(result.json()))    
    http.close()
    return None
def run():

    if (args['f'] is None and args['d'] is None):
        parser.error("Either -d or -f are requiered to provide list of domains.")

    if args['f']:
        if args['t'] is None:
            parser.error("-f requieres -t File Type (LIST, PM)")
        else:
            #readFile(args['f'],args['t'],args['o'],args['v'])
            
            a = readEdgeRC()
           

            if a is None:
                parser.error("Unable to read EdgeRc Credientials for PAPI section")
            j=papi(a,"GetRuleTree",args['v'])
            
            
    else:
        getCertificates(args['d'],args['o'],args['v'])

if __name__ == '__main__':
    run()

        