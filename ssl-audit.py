import OpenSSL , ssl,  argparse ,json, os.path, validators, requests, logging
from datetime import datetime
from dateutil.parser import parse
from urllib.parse import urljoin
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from pathlib import Path

#TODO: FIX logger format
#turn off logger
#send ouput to tmp file
#improve help documentation

parser = argparse.ArgumentParser(description='Certificate Expiration Audit\nLatest version and documentation can be found here:\nhttps://github.com/roymartinezblanco/Akamai-SSL-Expiration-Audit',formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--audit', type=str, choices=['account','config','file','list'], help='*required* Type of Audit to be done: [account,config,file,list]',
                    required=False)
parser.add_argument('--domains', nargs='+', type=str, help='List of domains to query.',
                    required=False)

parser.add_argument('--file-type', type=str, choices=['list','akamai'], help='File Type (list, akamai)',
                    required=False, default='akamai')  
parser.add_argument('--file', type=str, help='File with list of domains (one per line)',
                    required=False)         
parser.add_argument('--config-name',nargs='+', type=str, help='Name or List of Names to be audited.)',
                    required=False)          
parser.add_argument('--verbose', help='Show debug information',
                    required=False,  action='store_true')
parser.add_argument('--section', type=str, help='Select a Edgerc section other than the Default',
                    required=False)
parser.add_argument('--account-key', type=str, help='Account ID to Query for multi account management (switch key)',
                    required=False)        
                    
args = vars(parser.parse_args())

### Global Variables
#version= 0.1 INTERNAL
errors = []
items = {}
item_list= []
logger = logging.getLogger("SSL-AUDIT")


def configure_logging():
    logger.setLevel(logging.DEBUG)
    # Format for our loglines
    formatter = logging.Formatter("[%(asctime)s] - %(name)s - %(levelname)s - %(message)s")
    # Setup console logging
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    # Setup file logging as well
    # fh = logging.FileHandler(LOG_FILENAME)
    # fh.setLevel(logging.INFO)
    # fh.setFormatter(formatter)
    # logger.addHandler(fh)

def readObject(File,Ftype:str,configName:str=None):
    origins=[]
    if Ftype != "API":
        if os.path.exists(File):
            if Ftype == "list":
                if args['verbose']:
                    #print("...... Reading file '{}'.".format(File))
                    logger.debug("Reading file '{}'.".format(File))
                lines = [line.rstrip('\n') for line in open(File)]
                getCertificates(lines)
            else:

                try:
                    with open(File) as handle:
                        dictdump = json.loads(handle.read())                 
                except:
                    parser.error("Unable to Parse JSON File, please validate format.")
                else:
                    findOrigins(dictdump,origins,configName)

                    getCertificates(origins,configName)
        else:
            parser.error("The File {} does not exist!".format(File))
     
    else:
        if args['verbose']:
   
            logger.debug("Reading rules for the property '{}' .".format(configName))

        findOrigins(File,origins,configName)
        getCertificates(origins,configName)

def findOrigins(obj,origins:list,configName:str=None):

    for ok, ov in obj.items(): 
        if ok == "name" and ov == "origin":
            options = dict(obj["options"])

            if options["originType"] == "CUSTOMER":
                if args['verbose']:
       
                    logger.debug("Origin behavior found with the value '{}' on the configuration '{}'.".format(dict(obj["options"])["hostname"],configName))
                origins.append (dict(obj["options"])["hostname"])
    for k, v in obj.items():
        if isinstance(v,dict) or isinstance(v,list):
            if "values" not in k.lower():
                if isinstance(v,list):
                    if len(v) > 0:
                        for i in v:
                            if isinstance(i, dict):
                                findOrigins(dict(i),origins,configName)
                else:
                    findOrigins(v,origins,configName)

def printJson():
    
    if args['verbose']:
        logger.debug("Printing JSON.")
        logger.debug("[end]")
    if len(item_list) == 0:
        logger.error("No output generated to print!")
        return None
    if item_list[0] != {}:
        items['items'] = item_list
    if args['audit'] == "list":
        if len(errors) != 0:
            items['errors'] = errors
    formatted_json = json.dumps(items, sort_keys=False, indent=4)

    print(formatted_json)


def getCertificates(domains: list,configName:str=None):
    
    currentConfig={}
    if args['audit'] != "list" and args['audit'] != "file":
        currentConfig['propertyName'] = configName
    certs=[]
    er=[]
    for host in domains:
        if args['verbose']:

            logger.debug("Looking up the certificate for '{}' ".format(host))
        if "{{" in host:
            if args['verbose']:

                logger.warning("'{}' is a variable and will not be looked up!".format(host))
            er.append("'{}' is a variable and will not be looked up!".format(host))
        else:
            if validators.domain(host) != True:
                
                if args['verbose']:
                    if configName is not None:
          
                         logger.warning("'{}' is not a valid domain, on the configuration'{}'!".format(host,configName))
                    else:
           
                         logger.warning("'{}' is not a valid domain!".format(host))
                er.append("'{}' is not a valid domain!".format(host))
                continue
            try:
                hostname = host
                port = 443
                conn = ssl.create_connection((hostname,port), timeout=10)
   
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sock = context.wrap_socket(conn, server_hostname=hostname)
                certificate = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,certificate)
            except BaseException as e:
                if args['verbose']:
                    logger.error("Can't connect to '{}' error: {}".format(host,str(e)))
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

                logger.warning("No customer origins found on the configuration '{}.".format(configName))

        else:
            er.append("No customer origins found.")
            if args['verbose']:
          
                logger.warning("No customer origins found.")


    if certs != []:
        currentConfig['certificates'] = certs

        
    if er != []:
        if args['audit'] != "list":
            currentConfig['errors'] = er
        else:
            errors.append(er)
    item_list.append(currentConfig)

    return

def propertyManagerAPI(action:str,config:str=None,p:list=None):

    try:
        home = str(Path.home())
        edgerc = EdgeRc(home+"/.edgerc")
        
        if args['section']:
            section = args['section']
        else:
            section = 'papi'
        host = edgerc.get(section,'host')
    except Exception as e:
        logger.debug("Error Autehticating Edgerc {}.".format(home+edgerc))
    
    http = requests.Session()
    http.auth= EdgeGridAuth.from_edgerc(edgerc,section)
    validActions = ["ListGroups","ListContracts","ListProperties","GetRuleTree","SearchProperty"]
    if action not in validActions:
        
        parser.error("Error: PAPI Unknown Action")
    #ListGroups
    elif action == validActions[0]:
        if args['verbose']:
     
            logger.debug("Listing account groups with PAPI.")
        
        if args['account_key']:
            endpoint='/papi/v1/groups?accountSwitchKey={}'.format(args['account_key'])
        else:
            endpoint= '/papi/v1/groups'
        result = http.get(urljoin("https://" + host + "/", endpoint))
        response = json.loads(json.dumps(result.json()))
        http.close()
        return response
        

    #ListProperties
    elif action == validActions[2]:
        gps = propertyManagerAPI("ListGroups")

        if gps is None:
       
            logger.warning("No Groups were found in account!")
            return None
        elif gps['incidentId']:
            logger.error('{}'.format(gps['title']))
            return None
     
        for gp in gps['groups']['items']:
            for contract in gp['contractIds']:
                if args['verbose']:
    
                    logger.debug("Listing properties in '{}'/'{}' with PAPI.".format(gp['groupId'],contract))
 
                if args['account_key']:
                    endpoint= '/papi/v1/properties?contractId={}&groupId={}&accountSwitchKey={}'.format(contract,gp['groupId'],args['account_key'])
                else:
                    endpoint= '/papi/v1/properties?contractId={}&groupId={}'.format(contract,gp['groupId'])
                result = http.get(urljoin("https://" + host + "/", endpoint))
                http.close()
                response = json.loads(json.dumps(result.json()))
                for p in response['properties']['items']:

                    if p['productionVersion'] is None or p is None:
        
                        item={}
                        er=[]
                        er.append("The configuration has no active version in production.")
                        if args['verbose']:
                       
                            logger.warning("The configuration '{}' has no active version in production.".format(p['propertyName']))
                        item['propertyName']=p['propertyName']
                        item['errors']=er
                        item_list.append(item)
                    else:

                        p['propertyVersion']=p['productionVersion']
                        del p['productionVersion']
                        propertyManagerAPI("GetRuleTree","",p)

    elif action == validActions[3]:


        if args['verbose']:
  
            logger.debug("Getting rule tree for the '{}' property with PAPI.".format(p['propertyName']))
        if args['account_key']:
           
            endpoint= "/papi/v1/properties/{}/versions/{}/rules?contractId={}&groupId={}&validateRules=true&validateMode=fast&accountSwitchKey={}".format(
                p['propertyId'],
                p['propertyVersion'],
                p['contractId'],
                p['groupId'],
                args['account_key']
            )
        else:
            endpoint= "/papi/v1/properties/{}/versions/{}/rules?contractId={}&groupId={}&validateRules=true&validateMode=fast".format(
                p['propertyId'],
                p['propertyVersion'],
                p['contractId'],
                p['groupId']
            )

 
        result = http.get(urljoin("https://" + host + "/", endpoint))
        http.close()

        readObject(json.loads(json.dumps(result.json())) ,"API",p['propertyName'])

    elif action == validActions[4]:
        if args['verbose']:
         
            logger.debug("Looking for the configuration '{}'.".format(config))
        if args['account_key']:
            endpoint='/papi/v1/search/find-by-value?accountSwitchKey={}'.format(args['account_key'])
        else:
            endpoint='/papi/v1/search/find-by-value'
        postbody = {}
        postbody['propertyName'] = config
        result = http.post(urljoin("https://" + host + "/", endpoint),json.dumps(postbody), headers={"Content-Type": "application/json"})
        http.close()

        
        if result.json()['versions']['items'] == []:
            item={}
            er=[]
            item['propertyName']=config
            if args['verbose']:
             
                    logger.warning("The configuration '{}' was not found.".format(config))
            er.append("The configuration was not found.")
            item['errors']=er
             
            item_list.append(item)
            return 
        else:
            if args['verbose']:
       
                logger.debug("The configuration '{}' was found.".format(config))
            prodversion = None
            for i in result.json()['versions']['items']:
                if i['productionStatus'] == "ACTIVE":
                    prodversion = True
                    propertyManagerAPI("GetRuleTree","",i)
            if prodversion is None:
                item={}
                er=[]
                if args['verbose']:
                 
                    logger.warning("The configuration '{}' has no active version in production.".format(config))
                er.append("The configuration has no active version in production.")
                item['propertyName']=config
                item['errors']=er
             
                item_list.append(item)
  
                
            return json.loads(json.dumps(result.json()))
        

    return None
def main():
    
    if not args['audit']:
        parser.print_help()
    if args['verbose']:
        configure_logging()
     
        logger.info("[start]")
    if args['audit'] == "list":
        if args['domains'] is None:
            parser.error("--domains is required to provide list of domains.")
        else:
            getCertificates(args['domains'])
            printJson()
    elif (args['audit'] == "file"):
        if (args['file'] is None):
            parser.error("--file is required to provide the file to audited.")
        else:

            readObject(args['file'],args['file_type'])
            printJson()

    elif (args['audit'] == "config"):  
        if args['config_name'] is None:
            parser.error("--config-name is required to provide configuration to be audited.")
        else:    
            for i in args['config_name']:
                propertyManagerAPI("SearchProperty",i)
                
            printJson()
    elif (args['audit'] == "account"):
        #a = readEdgeRC() 

        propertyManagerAPI("ListProperties")
        printJson()

   
if __name__ == '__main__':
    main()

        