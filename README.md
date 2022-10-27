# listDomainShares
List shares found on all computers part of the domain computers group

## Info
I needed a project similar to [sharpshares - mitchmoser](https://github.com/mitchmoser/SharpShares) and [sharpshares - djhohnstein](https://github.com/djhohnstein/SharpShares) but written in python. This is the result of that code. I don't claim any of this code as my own and it probably will break when you try to run it, but for now it works for my current engagement. Maybe one day I will come back and clean up the argparsing and dead code.

## Who did I steal code from
I barely wrote any of this code, most(almost all) of it was borrowed. These projects are fantastic and I stand on the shoulders of giants. 
Ldap queries from [sharpshares - mitchmoser](https://github.com/mitchmoser/SharpShares)
Python base from [GetADUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetADUsers.py)
Python LDAP from [ldap.py](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/ldap/ldap.py)
Python SMB from  [smbmap.py](https://github.com/ShawnDEvans/smbmap)

## Installation
### Pipx
1. Clone the repo
2. `pipx install .`
3. Profit??

### Python virtulenv
1. Clone the repo
2. `python -m pip install -r reqirements.txt`
3. Use the script

## Usage
```
python .\GetDomainShares.py -h

usage: GetDomainShares.py [-h] [-user username] [-all] [-ts] [-debug] [-no-write-check] [-depth DEPTH] [-csv FILE] [-pretty] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                          [-aesKey hex key] [-dc-ip ip address] [-dc-host hostname] [-ldapq LDAPQ]
                          target

Queries target domain for users data

positional arguments:
  target                domain[/username[:password]]

optional arguments:
  -h, --help            show this help message and exit
  -user username        Requests data for specific user
  -all                  Return all users, including those with no email addresses and disabled accounts. When used with -user it will return user's info even if the
                        account is disabled
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -no-write-check       Skip check to see if drive grants WRITE access.
  -depth DEPTH          Traverse a directory tree to a specific depth. Default is 5.
  -csv FILE             Output to a CSV file, ex --csv shares.csv
  -pretty               Force pretty print
  -ldapq LDAPQ          LDAP query to use

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it
                        will use the ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter
  -dc-host hostname     Hostname of the domain controller to use. If ommited, the domain part (FQDN) specified in the account parameter will be used
```

## Example
### Output results to results.csv
```
PS> python .\GetDomainShares.py -ldapq all -dc-ip 192.168.126.10 -csv results.csv empire.net/vader:P@ssw0rd
[+] Query: all enabled computers with "primary" group "Domain Computers"

Computer: Dev2016.empire.net
Computer: Win10-Dev.empire.net
```

### Pretty print results
```
PS> python .\GetDomainShares.py -ldapq all -dc-ip 192.168.126.10 empire.net/vader:P@ssw0rd
[+] Query: all enabled computers with "primary" group "Domain Computers"

Computer: Dev2016.empire.net
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        someshare                                               READ, WRITE
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
        test                                                    READ, WRITE     test share

Computer: Win10-Dev.empire.net
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        Users                                                   READ ONLY
```

### Output results to results.csv and pretty print
```
```
PS> python .\GetDomainShares.py -ldapq all -dc-ip 192.168.126.10 -csv results.csv -pretty empire.net/vader:P@ssw0rd
[+] Query: all enabled computers with "primary" group "Domain Computers"

Computer: Dev2016.empire.net
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        someshare                                               READ, WRITE
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
        test                                                    READ, WRITE     test share

Computer: Win10-Dev.empire.net
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        Users                                                   READ ONLY
```
```