import OpenSSL , ssl,  argparse ,json, os.path, validators, requests 
from datetime import datetime
from dateutil.parser import parse
from urllib.parse import urljoin
from akamai.edgegrid import EdgeGridAuth
from pathlib import Path
#from pygments import highlight, lexers, formatters


parser = argparse.ArgumentParser(description='Akamai Cert Validity Automation Script')
parser.add_argument('--audit', type=str, choices=['account','config','file','list'], help='Type of Audit to be done: [account,config,file,list]',
                    required=True)
parser.add_argument('--domains', nargs='+', type=str, help='<Required> List of domains to query.',
                    required=False)

parser.add_argument('--file-type', type=str, choices=['list','akamai'], help='File Type (list, akamai)',
                    required=False, default='akamai')  
parser.add_argument('--file', type=str, help='File with list of domains (one per line)',
                    required=False)         
parser.add_argument('--config-name',nargs='+', type=str, help='Name or List of Names to be audited.)',
                    required=False)          
parser.add_argument('--verbose', help='Show Errors',
                    required=False,  action='store_true')
parser.add_argument('--section', type=str, help='File with list of domains (one per line)',
                    required=False)
parser.add_argument('--switch-key', type=str, help='File with list of domains (one per line)',
                    required=False)        
                    
args = vars(parser.parse_args())

### Global Variables
#version= 0.1
errors = []
items = {}
item_list= []


class Credentials:
    def __init__(self):
        self.client_secret = ""
        self.host = ""
        self.access_token = ""
        self.client_token = ""

def readObject(File,Ftype:str,configName:str=None):
    origins=[]
    if Ftype != "API":
        if os.path.exists(File):
            if Ftype == "list":
                if args['verbose']:
                    print("...... Reading file '{}'.".format(File))
                lines = [line.rstrip('\n') for line in open(File)]
                getCertificates(lines)
            else:

                try:
                    with open(File) as handle:
                        dictdump = json.loads(handle.read())                 
                except:
                    parser.error("Unable to Parse JSON File, please validate format.")
                else:
                    finditem(dictdump,origins,configName)

                    getCertificates(origins,configName)
        else:
            parser.error("The File {} does not exist!".format(File))
     
    else:
        if args['verbose']:
            print("...... Reading rules for the property '{}' .".format(configName))

        finditem(File,origins,configName)
        getCertificates(origins,configName)

def finditem(obj,origins:list,configName:str=None):

    for ok, ov in obj.items(): 
        if ok == "name" and ov == "origin":
            options = dict(obj["options"])

            if options["originType"] == "CUSTOMER":
                if args['verbose']:
                    print("...... Origin behavior found with the value '{}' on the configuration '{}'.".format(dict(obj["options"])["hostname"],configName))

                origins.append (dict(obj["options"])["hostname"])
    for k, v in obj.items():
        if isinstance(v,dict) or isinstance(v,list):
            if "values" not in k.lower():
                if isinstance(v,list):
                    if len(v) > 0:
                        for i in v:
                            if isinstance(i, dict):
                                finditem(dict(i),origins,configName)
                else:
                    finditem(v,origins,configName)

def printJson():
    
    if args['verbose']:
        print("...... Printing JSON.")     
        print("...... [end] {}".format(datetime.now()))    
    if str(item_list) != "[{}]":
        items['items'] = item_list
    if args['audit'] == "list":
        items['errors'] = errors
    formatted_json = json.dumps(items, sort_keys=False, indent=4)
    #colorful_json= pygments.highlight(formatted_json, pygments.lexers.data.JsonLexer(),formatters.html())
    #print(
    #colorful_json = highlight(formatted_json.encode("utf-8"), lexers.JsonLexer(), formatters.Terminal256Formatter())
    #colorful_json = highlight(json.dumps(items, indent = 4, sort_keys=False), lexers.data.JsonLexer(), formatters.terminal.Formatter())

    print(formatted_json)


def getCertificates(domains: list,configName:str=None):
    
    currentConfig={}
    if args['audit'] != "list" and args['audit'] != "file":
        currentConfig['propertyName'] = configName
    certs=[]
    er=[]
    for host in domains:
        if args['verbose']:
            print("...... Looking up the certificate for '{}' ".format(host))
        if "{{" in host:
            if args['verbose']:
                print("...... [warning] '{}' is a variable and will not be looked up!".format(host))
            er.append("'{}' is a variable and will not be looked up!".format(host))
        else:
            if validators.domain(host) != True:
                
                if args['verbose']:
                    if configName is not None:
                        print("...... [warning] '{}' is not a valid domain, on the configuration'{}'!".format(host,configName))
                    else:
                        print("...... [warning] '{}' is not a valid domain!".format(host))
                er.append("'{}' is not a valid domain!".format(host))
                continue
            try:
                hostname = host
                port = 443
                conn = ssl.create_connection((hostname,port), timeout=10)
                #conn.settimeout(10)
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sock = context.wrap_socket(conn, server_hostname=hostname)
                certificate = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,certificate)
            except BaseException as e:
                if args['verbose']:
                    print("...... [warning] Can't connect to '{}' error: {}".format(host,str(e)))
                er.append("Can't connect to '{}' error: {}".format(host,str(e)))
            else:
                serial= '{0:x}'.format(x509.get_serial_number())
                
                exp_date = str(x509.get_notAfter().decode('utf-8'))
                dt = parse(exp_date)

                daystoexp=dt.replace(tzinfo=None)-datetime.utcnow()


                item = {}
                item['Domain'] = str(host)
                item['Serial'] = str(serial)
                item['ExpDate'] =  str(dt.date())
                item['DaysLeft']  =  daystoexp.days
 
                certs.append(item)
    if domains == []:

        if configName is not None:
            er.append("No customer origins found on the configuration '{}'.".format(configName))
            if args['verbose']:
                print("...... [warning] No customer origins found on the configuration '{}.".format(configName))

        else:
            er.append("No customer origins found.")
            if args['verbose']:
                print("...... [warning] No customer origins found.")


    if certs != []:
        currentConfig['certicates'] = certs

        
    if er != []:
        if args['audit'] != "list":
            currentConfig['errors'] = er
        else:
            errors.append(er)
    item_list.append(currentConfig)

    return

def readEdgeRC():
    
    if args['section']:
        section='['+args['section']+']'
    else: 
        section='[default]'

    a = Credentials()
    home = str(Path.home())
    edgerc = '/.edgerc'
    if args['verbose']:
        print("...... Reading Edgerc {}.".format(home+edgerc))
    if os.path.exists(home+edgerc):
        with open(home+edgerc) as fp:
            selectedProfile=False
            line = fp.readline()
            while line:
                line = fp.readline()
                if line.strip().lower() == section:
                    selectedProfile=True
                if line.strip() == "":
                    selectedProfile=False
                if selectedProfile == True and line.strip().lower() != section:
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
        if args['verbose']:
            print("...... [warning] The File {} does not exist!".format(home+edgerc))
        parser.error("The File {} does not exist!".format(home+edgerc))

def papi(a: Credentials,action:str,config:str=None,p:list=None):
    http = requests.Session()
    http.auth= EdgeGridAuth(
            client_token=a.client_token,
            client_secret=a.client_secret,
            access_token=a.access_token
        )
    validActions = ["ListGroups","ListContracts","ListProperties","GetRuleTree","SearchProperty"]
    if action not in validActions:
        
        parser.error("Error: PAPI Unknown Action")
    #ListGroups
    elif action == validActions[0]:
        if args['verbose']:
            print("...... Listing account groups with PAPI.")
        
        if args['switch_key']:
            endpoint='/papi/v1/groups?accountSwitchKey={}'.format(args['switch_key'])
        else:
            endpoint= '/papi/v1/groups'
        result = http.get(urljoin("https://" + a.host + "/", endpoint))
        http.close()
    #ListProperties
    elif action == validActions[2]:
        gps = papi(a,"ListGroups")
        for gp in gps['groups']['items']:
            for contract in gp['contractIds']:
                if args['verbose']:
                    print("...... Listing properties in '{}'/'{}' with PAPI.".format(gp['groupId'],contract))
 
                if args['switch_key']:
                    endpoint= '/papi/v1/properties?contractId={}&groupId={}&accountSwitchKey={}'.format(contract,gp['groupId'],args['switch_key'])
                else:
                    endpoint= '/papi/v1/properties?contractId={}&groupId={}'.format(contract,gp['groupId'])
                result = http.get(urljoin("https://" + a.host + "/", endpoint))
                http.close()
                response = json.loads(json.dumps(result.json()))
                for p in response['properties']['items']:

                    if p['productionVersion'] is None or p is None:
                        #print(False)
                        item={}
                        er=[]
                        er.append("The configuration has no active version in production.")
                        if args['verbose']:
                            print("...... [warning] The configuration '{}' has no active version in production.".format(p['propertyName']))
                        item['propertyName']=p['propertyName']
                        item['errors']=er
                        item_list.append(item)
                    else:
                        #print("here")
                        p['propertyVersion']=p['productionVersion']
                        del p['productionVersion']
                        papi(a,"GetRuleTree","",p)

    elif action == validActions[3]:


        if args['verbose']:
            print("...... Getting rule tree for the '{}' property with PAPI.".format(p['propertyName']))
        if args['switch_key']:
           
            endpoint= "/papi/v1/properties/{}/versions/{}/rules?contractId={}&groupId={}&validateRules=true&validateMode=fast&accountSwitchKey={}".format(
                p['propertyId'],
                p['propertyVersion'],
                p['contractId'],
                p['groupId'],
                args['switch_key']
            )
        else:
            endpoint= "/papi/v1/properties/{}/versions/{}/rules?contractId={}&groupId={}&validateRules=true&validateMode=fast".format(
                p['propertyId'],
                p['propertyVersion'],
                p['contractId'],
                p['groupId']
            )

 
        result = http.get(urljoin("https://" + a.host + "/", endpoint))
        http.close()

        readObject(json.loads(json.dumps(result.json())) ,"API",p['propertyName'])

    elif action == validActions[4]:
        if args['verbose']:
            print("...... Looking for the configuration '{}'.".format(config))
        if args['switch_key']:
            endpoint='/papi/v1/search/find-by-value?accountSwitchKey={}'.format(args['switch_key'])
        else:
            endpoint='/papi/v1/search/find-by-value'
        postbody = {}
        postbody['propertyName'] = config
        result = http.post(urljoin("https://" + a.host + "/", endpoint),json.dumps(postbody), headers={"Content-Type": "application/json"})
        http.close()

        
        if result.json()['versions']['items'] == []:
            item={}
            er=[]
            item['propertyName']=config
            if args['verbose']:
                    print("...... [warning] The configuration '{}' was not found.".format(config))
            er.append("The configuration was not found.")
            item['errors']=er
             
            item_list.append(item)
            return 
        else:
            if args['verbose']:
                print("...... The configuration '{}' was found.".format(config))
            prodversion = None
            for i in result.json()['versions']['items']:
                if i['productionStatus'] == "ACTIVE":
                    prodversion = True
                    papi(a,"GetRuleTree","",i)
            if prodversion is None:
                item={}
                er=[]
                if args['verbose']:
                    print("...... [warning] The configuration '{}' has no active version in production.".format(config))
                er.append("The configuration has no active version in production.")
                item['propertyName']=config
                item['errors']=er
             
                item_list.append(item)
  
                
            return json.loads(json.dumps(result.json()))
        

    return None
def run():
    if args['verbose']:
        print("...... [start] {}".format(datetime.now()))
    if args['audit'] == "list":
        if args['domains'] is None:
            parser.error("--domains is requiered to provide list of domains.")
        else:
            getCertificates(args['domains'])
            printJson()
    elif (args['audit'] == "file"):
        if (args['file'] is None):
            parser.error("--file is requiered to provide the file to audited.")
        else:

            readObject(args['file'],args['file_type'])
            printJson()

    elif (args['audit'] == "config"):  
        if args['config_name'] is None:
            parser.error("--config-name is requiered to provide configuration to be audited.")
        else:    
            a = readEdgeRC()  
            if a is None:
                parser.error("Unable to read EdgeRc Credientials for PAPI section")

            else:
                for i in args['config_name']:

                    papi(a,"SearchProperty",i)
                    
                printJson()
    elif (args['audit'] == "account"):
        a = readEdgeRC() 

        papi(a,"ListProperties")
        printJson()

   
if __name__ == '__main__':
    run()

        