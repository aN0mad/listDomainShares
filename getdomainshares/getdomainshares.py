from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import argparse
import logging
import sys
from datetime import datetime
import socket
import os
import ntpath
import random
from termcolor import colored as termcolored
import csv

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_WRITE_DATA

PERM_DIR = ''.join(random.sample('ABCDEFGHIGJLMNOPQRSTUVWXYZ', 10))
USE_TERMCOLOR=True

def colored(msg, *args, **kwargs):
    global USE_TERMCOLOR
    if USE_TERMCOLOR:
        return termcolored(msg, *args, **kwargs)
    return msg

class GetDomainShares:
    __ldapConn = None
    def __init__(self, username, password, domain, cmdLineOptions):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = None
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        #[!] in this script the value of -dc-ip option is self.__kdcIP and the value of -dc-host option is self.__kdcHost
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        self.__requestUser = cmdLineOptions.user
        self.__all = cmdLineOptions.all
        self.__ldapq = cmdLineOptions.ldapq # TODO: map this in cmdLineOptions
        self.__computerNames = []
        self.__write_check = cmdLineOptions.write_check
        self.__depth = cmdLineOptions.depth
        self.__exclude = []
        self.csv = False
        self.writer = None
        self.verbose = True
        self.grepable = False
        self.outfile = None
        self.pattern = None
        self.list_files = False
        self.prettyprint = cmdLineOptions.pretty
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        # Let's calculate the header and format
        self.__header = ["Name", "Email", "PasswordLastSet", "LastLogon"] # TODO: This is not needed
        # Since we won't process all rows at once, this will be fixed lengths
        self.__colLen = [20, 30, 19, 19] # TODO: This is not needed
        self.__outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(self.__colLen)]) # TODO: This needs to be updated
    
    def run(self):
        if self.__kdcHost is not None:
            self.__target = self.__kdcHost
        else:
            if self.__kdcIP is not None:
                self.__target = self.__kdcIP
            else:
                self.__target = self.__domain

            if self.__doKerberos:
                logging.info('Getting machine hostname')
                self.__target = self.getMachineName(self.__target)

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcIP)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcIP)
            self.__ldapConn = ldapConnection
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcIP)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcIP)
                self.__ldapConn = ldapConnection
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    logging.critical("NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos "
                                     "authentication instead.")
                else:
                    if self.__kdcIP is not None and self.__kdcHost is not None:
                        logging.critical("If the credentials are valid, check the hostname and IP address of KDC. They "
                                         "must match exactly each other.")
                raise

        # logging.info('Querying %s for information about domain.' % self.__target)
        # # Print header
        # print((self.__outputFormat.format(*self.__header)))
        # print(('  '.join(['-' * itemLen for itemLen in self.__colLen])))

        # # Building the search filter
        # if self.__all:
        #     searchFilter = "(&(sAMAccountName=*)(objectCategory=user)"
        # else:
        #     searchFilter = "(&(sAMAccountName=*)(mail=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))" % UF_ACCOUNTDISABLE

        # if self.__requestUser is not None:
        #     searchFilter += '(sAMAccountName:=%s))' % self.__requestUser
        # else:
        #     searchFilter += ')'

        # try:
        #     logging.debug('Search Filter=%s' % searchFilter)
        #     sc = ldap.SimplePagedResultsControl(size=100)
        #     ldapConnection.search(searchFilter=searchFilter,
        #                           attributes=['sAMAccountName', 'pwdLastSet', 'mail', 'lastLogon'],
        #                           sizeLimit=0, searchControls = [sc], perRecordCallback=self.processRecord)
        # except ldap.LDAPSearchError:
        #         raise

        # ldapConnection.close()
    
    def doLDAPSearch(self, searchFilter):
        try:
            logging.debug('Search Filter=%s' % searchFilter)
            sc = ldap.SimplePagedResultsControl(size=100)
            self.__ldapConn.search(searchFilter=searchFilter,
                                  sizeLimit=0, searchControls = [sc], perRecordCallback=self.processHosts)
        except ldap.LDAPSearchError:
                raise

    # Return: 1 = failed
    def getADComputers(self):
        # vars
        description = ""
        filter = ""
        searchGlobalCatalog = True

        if self.__ldapq == "all":
            description = "all enabled computers with \"primary\" group \"Domain Computers\""
            filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
        elif self.__ldapq == "dc":
            description = "all enabled Domain Controllers (not read-only DCs)"
            filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=8192))")
        elif self.__ldapq == "exclude-dc":
            description = "all enabled computers that are not Domain Controllers or read-only DCs"
            filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))")
        elif self.__ldapq == "servers":
            searchGlobalCatalog = False; # operatingSystem attribute is not replicated in Global Catalog
            description = "all enabled servers"
            filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*))")
        elif self.__ldapq == "servers-exclude-dc":
            searchGlobalCatalog = False; #operatingSystem attribute is not replicated in Global Catalog
            description = "all enabled servers excluding Domain Controllers or read-only DCs"
            filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))")
        else:
            print("[!] Invalid LDAP filter: {0}".format(filter))
            return 1
        # Don't search globalCatalog for now
        # if searchGlobalCatalog:

        print("[+] Query: {0}".format(description))
        self.doLDAPSearch(filter)
        
    
    #def getShareForComputer(self):

        
    
    def processHosts(self, item):
        computerName = ""
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return
        try:
            for attribute in item['attributes']:
                if str(attribute['type']) == 'dNSHostName':
                    computerName = attribute['vals'][0].asOctets().decode('utf-8')
        except Exception as e:
            print("Error printing attributes")
            print(e)
            return

        print() 
        print("Computer: {0}".format(computerName))
        
        #print(computerName)
        try:
            ip = socket.gethostbyname(computerName)
            conn = self.login(ip,445) # TODO: This should be a dynamic port
            if conn:
                shares = self.get_shares(conn)
                lsshare = False
                lspath = False
                self.output_shares(ip, lsshare, lspath, conn, self.__write_check, self.__depth)
        except Exception as e:
            if self.verbose:
                print("Error for host {name}: {error}".format(name=computerName,error=e))
            
    
    def output_shares(self, host, lsshare, lspath, conn, write_check=True, depth=5, ):
        shareList = [(lsshare,'')] if lsshare else self.get_shares(conn)
        share_privs = ''
        share_tree = {}
        for share in shareList:
            if share[0].lower() not in self.__exclude:
                share_name = share[0]
                share_comment = share[1]
                share_tree[share_name] = {}
                canWrite = False
                readonly = False
                noaccess = False
                if write_check:
                    try:

                        root = PERM_DIR.replace('/','\\')
                        root = ntpath.normpath(root)
                        self.create_dir(conn, share_name, root)
                        share_tree[share_name]['privs'] = 'READ, WRITE'
                        canWrite = True
                        try:
                            self.remove_dir(conn, share_name, root)
                        except Exception as e:
                            print('\t[!] Unable to remove test directory at \\\\%s\\%s\\%s, please remove manually' % (host, share_name, root))
                    except Exception as e:
                        exc_type, exc_obj, exc_tb = sys.exc_info()
                        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                        #print(exc_type, fname, exc_tb.tb_lineno)
                        sys.stdout.flush()
                    if not canWrite:
                        try:
                            root = PERM_DIR.replace('/','\\')
                            root = ntpath.normpath(root)
                            self.create_file(conn, share_name, root)
                            share_tree[share_name]['privs'] = colored('READ, WRITE', 'green')
                            canWrite = True
                            try:
                                self.remove_file(conn, share_name, root)
                            except Exception as e:
                                print('\t[!] Unable to remove test file at \\\\%s\\%s\\%s, please remove manually' % (host, share_name, root))
                        except Exception as e:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            #print(exc_type, fname, exc_tb.tb_lineno)
                            sys.stdout.flush()

                try:
                    if conn.listPath(share_name, self.pathify('/')) and canWrite == False:
                        readonly = True
                        share_tree[share_name]['privs'] = 'READ ONLY'
                except Exception as e:
                    noaccess = True
                    share_tree[share_name]['privs'] = 'NO ACCESS'

                share_tree[share_name]['comment'] = share_comment
                contents = {}
                
                try:
                    if noaccess == False:
                        dirList = ''
                        if lspath:
                            path = lspath
                        else:
                            path = '/'
                        if self.list_files:
                            if self.pattern:
                                print('[+] Starting search for files matching \'%s\' on share %s.' % (self.pattern, share[0]))
                            contents = self.list_path(host, share_name, path, depth)
                except Exception as e:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    print('[!] Something weird happened: {} on line {}'.format(e, exc_tb.tb_lineno))
                    sys.stdout.flush()
                    sys.exit()
                share_tree[share_name]['contents'] = contents

        self.to_string(share_tree, host)
    
    def pathify(self, path):
        root = ''
        root = ntpath.join(path,'*')
        root = root.replace('/','\\')
        root = root.replace('\\\\','\\')
        root = ntpath.normpath(root)
        return root
    
    def create_dir(self, conn, share, path):
        #path = self.pathify(path)
        conn.createDirectory(share, path)
    
    def remove_dir(self, conn, share, path):
        #path = self.pathify(path)
        conn.deleteDirectory(share, path)
    
    def create_file(self, conn, share, path):
        tid = conn.connectTree(share)
        conn.createFile(tid, path, desiredAccess=FILE_WRITE_DATA)
    
    def remove_file(self, conn, share, path):
        #path = self.pathify(path)
        conn.deleteFile(share, path)
    
    def to_string(self, share_tree, host):
        header = '\tDisk{}\tPermissions\tComment\n'.format(' '.ljust(50))
        header += '\t----{}\t-----------\t-------'.format(' '.ljust(50))
        heads_up = False
        try:
            for item in share_tree.keys():
                if share_tree[item]['privs'] == 'READ, WRITE':
                    share_name_privs = colored('READ, WRITE', 'green')
                if share_tree[item]['privs'] == 'READ ONLY':
                    share_name_privs = colored('READ ONLY', 'yellow')
                if share_tree[item]['privs'] == 'NO ACCESS':
                    share_name_privs = colored('NO ACCESS', 'red')
                if self.csv and not self.list_files:
                    row = {}
                    row['Host'] = host
                    row['Share'] = item
                    row['Privs'] = share_tree[item]['privs'].replace(',','').replace(' ', '_')
                    row['Comment'] = share_tree[item]['comment'].replace('\r','').replace('\n', '')
                    self.writer.writerow(row)
                if self.verbose == False and 'NO ACCESS' not in share_tree[item]['privs'] and self.grepable == False and not self.pattern and self.csv == False:
                    if heads_up == False:
                        print(header)
                        heads_up = True
                    print('\t{}\t{}\t{}'.format(item.ljust(50), share_name_privs, share_tree[item]['comment'] ) )
                elif self.verbose and self.grepable == False and self.csv == False and not self.pattern:
                    if heads_up == False:
                        print(header)
                        heads_up = True
                    print('\t{}\t{}\t{}'.format(item.ljust(50), share_name_privs, share_tree[item]['comment'] ) )
                elif self.prettyprint:
                    if heads_up == False:
                        print(header)
                        heads_up = True
                    print('\t{}\t{}\t{}'.format(item.ljust(50), share_name_privs, share_tree[item]['comment'] ) )
                for path in share_tree[item]['contents'].keys():
                    if self.grepable == False and self.csv == False and self.verbose:
                        print('\t.\{}\{}'.format(item, self.pathify(path)))
                    for file_info in share_tree[item]['contents'][path]:
                        isDir = file_info['isDir']
                        readonly = file_info['readonly']
                        filesize = file_info['filesize']
                        date = file_info['date']
                        filename = file_info['filename']
                        if (self.verbose and self.grepable == False and self.csv == False) and ((self.dir_only == True and isDir == 'd') or ( (isDir == 'f' or isDir == 'd') and self.dir_only == False)):
                            print('\t%s%s--%s--%s-- %s %s\t%s' % (isDir, readonly, readonly, readonly, str(filesize).rjust(16), date, filename))
                        elif self.grepable:
                            if filename != '.' and filename != '..':
                                if (self.dir_only == True and isDir == 'd') or ( (isDir == 'f' or isDir == 'd') and self.dir_only == False):
                                    self.outfile.write('host:{}, share:{}, privs:{}, isDir:{}, path:{}{}\{}, fileSize:{}, date:{}\n'.format(host, item, share_tree[item]['privs'].replace(',','').replace(' ', '_'), isDir, item, self.pathify(path).replace('\*',''), filename, str(filesize), date))
                        elif self.csv:
                            if filename != '.' and filename != '..':
                                if (self.dir_only == True and isDir == 'd') or ( (isDir == 'f' or isDir == 'd') and self.dir_only == False):
                                    row = {}
                                    row['Host'] = host
                                    row['Share'] = item
                                    row['Privs'] = share_tree[item]['privs'].replace(',','').replace(' ', '_')
                                    row['isDir'] = isDir
                                    row['Path'] = '{}{}\{}'.format(item, self.pathify(path).replace('\*',''), filename)
                                    row['fileSize'] = str(filesize)
                                    row['Date'] = date
                                    self.writer.writerow(row) 
        except Exception as e:
            print('[!] Bummer: ', e)
            
    
    def login(self, host, port):
        '''
        login: Login to smb using the credentials in the self object.

        Returns: SMBConnection or False
        '''
        try:
            if port == 445:
                smbconn = SMBConnection(host, host, sess_port=445, timeout=4)
                smbconn.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                smbconn = SMBConnection('*SMBSERVER', host, sess_port=139, timeout=4)
                smbconn.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            '''
            if self.smbconn[host].isGuestSession() > 0:
                if verbose and not self.grepable:
                    print('[+] Guest SMB session established on %s...' % (host))
            else:
                if verbose and not self.grepable:
                    print('[+] User SMB session established on %s...' % (host))
            '''
            return smbconn

        except Exception as e:
            if self.verbose:
                print('[!] Authentication error on %s' % (host))
            return False

    def get_shares(self, conn):
        try:
            shareList = conn.listShares()
            shares = []
            for item in range(len(shareList)):
                shares.append( (shareList[item]['shi1_netname'][:-1], shareList[item]['shi1_remark'][:-1]) )
            return shares
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print('[!] Something weird happened: {} on line {}'.format(e, exc_tb.tb_lineno))
            sys.stdout.flush()
            self.kill_loader()
            #sys.exit()

            

# Process command-line arguments.
def main():

    parser = argparse.ArgumentParser(add_help = True, description = "Queries target domain for users data")

    parser.add_argument('target', action='store', help='domain[/username[:password]]')
    parser.add_argument('-user', action='store', metavar='username', help='Requests data for specific user ')
    parser.add_argument('-all', action='store_true', help='Return all users, including those with no email '
                                                           'addresses and disabled accounts. When used with -user it '
                                                          'will return user\'s info even if the account is disabled')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument("-no-write-check", dest='write_check', action='store_false', help="Skip check to see if drive grants WRITE access.")
    parser.add_argument("-depth", dest="depth", default=5, help="Traverse a directory tree to a specific depth. Default is 5.")
    parser.add_argument("-csv", metavar="FILE", dest="csv", default=False, help="Output to a CSV file, ex --csv shares.csv")
    parser.add_argument("-pretty", action='store_true', default=False, help="Force pretty print")
    parser.add_argument('-ldapq', action='store', help='LDAP query to use')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller. If '
                                                                              'ommited it use the domain part (FQDN) '
                                                                              'specified in the target parameter')
    group.add_argument('-dc-host', action='store', metavar='hostname', help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.target)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    try:
        executer = GetDomainShares(username, password, domain, options)

        if options.csv:
            executer.outfile = open(options.csv, 'w', newline='')
            executer.csv = True
            csv_fields = ['Host', 'Share', 'Privs', 'Comment']
            executer.writer = csv.DictWriter(executer.outfile, csv_fields)
            executer.writer.writeheader()

        executer.run()
        executer.getADComputers()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

if __name__ == '__main__':
    main()