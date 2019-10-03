import argparse
import sys
import base64
import os
import yaml
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64decode
from base64 import b64encode
import hashlib
import pyperclip
import secrets
from tabulate import tabulate


def parser():
    myparser = argparse.ArgumentParser()

    # primary required arguments for storing encrypted passwords, listing all credentials, finding credentials from stored credentials
    # and retreiving credentials
    primary_group = myparser.add_mutually_exclusive_group(required=True)

    primary_group.add_argument('-rt',
                               '--retrieve_credentials',
                               action='store',
                               nargs=1,
                               metavar='[website]',
                               help='retrieve credentials for a website/service NOTE: username is displayed but password is automatically copied to clipboard')

    primary_group.add_argument('-st',
                               '--store_credentials',
                               action='store',
                               nargs='+',
                               metavar='[website/service] [username] [password]',
                               help=''
                               )

    primary_group.add_argument('-l',
                               '--list_credentials',
                               action='store_true',
                               help='list all saved credentials')

    primary_group.add_argument('-del',
                               '--delete_credentials',
                               action='store',
                               nargs=1,
                               metavar='[website/servie]',
                               help='delete credentials of speicfied website/service')

    primary_group.add_argument('-cgp',
    							'--change_globalpassword',
    						    action='store_true',
    							help='change global password')

    secondary_group = myparser.add_mutually_exclusive_group()

    secondary_group.add_argument('-gp',
    							'--generate_password',
                                 action='store',
                                 nargs=1,
                                 type=int,
                                 metavar='[password_size]',
                                 help='generate cryptographically secure random password of given size NOTE: used with store_credentials flag')

    secondary_group.add_argument('-gpn',
    							'--generate_password_nosymbol',
                                 action='store',
                                 nargs=1,
                                 type=int,
                                 metavar='[password_size]',
                                 help='generate cryptographically secure random password of given size but symbols are ommited NOTE: used with store_credentials flag')

    return myparser


def encryptpass(passphrase, salt_param, password):
    passkey = passphrase.encode()
    salt = salt_param
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey))
    f = Fernet(key)
    token = f.encrypt(password.encode())
    return token

def decryptpass(passphrase, salt_param, password):
    passkey = passphrase.encode()
    salt = salt_param
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey))
    f = Fernet(key)
    token = f.decrypt(password.encode())
    return token

def generate_password_func(size):
    passw=''
    for i in range(size):
        passw=passw+chr(secrets.choice(range(32,126)))
    return passw

def generate_no_symbol_func(size):
    li=[]
    passw=''
    for w in range(48,58):
        li.append(chr(w))
    for x in range(65,91):
        li.append(chr(x))
    for y in range(97,123):
        li.append(chr(y))
    for z in range(size):
        passw=passw+secrets.choice(li)
    return passw

def plot_table(dict1, table_salt, table_passphrase):
    table=[]
    headers=['\u001b[31;1m'+'service/website'+'\u001b[0m', '\u001b[31;1m'+'login'+'\u001b[0m', '\u001b[31;1m'+'password'+'\u001b[0m']
    for i in dict1.keys():
        li=[]
        username=decryptpass(table_passphrase, table_salt, dict1[i]['username'])
        password=decryptpass(table_passphrase, table_salt, dict1[i]['password'])
        li.append(i)
        li.append(username.decode())
        li.append(password.decode())
        table.append(li)
    print(tabulate(table, headers, tablefmt='fancy_grid'))

def delete_credentials(dict1, service_website):
    dict1.pop(service_website)
    return dict1

		

def main():
    home=os.path.expanduser('~')
    if os.path.exists(f'{home}/passkeys/') == False:
    	os.mkdir(f'{home}/passkeys')
    else:
    	pass

    parser0 = parser()

    if len(sys.argv) == 1:
        parser0.print_help()
        sys.exit(0)

    args = parser0.parse_args()

    if args.store_credentials:
        if args.store_credentials != None and len(args.store_credentials) > 3:
            parser0.error(
                '--st, --store_credentials require no more than three arguments')
        elif args.store_credentials != None and len(args.store_credentials) < 2:
            parser0.error(
                '--st, --store_credentials require at least two arguments')
        elif args.store_credentials != None and (len(args.store_credentials) == 2 and (args.generate_password == None and args.generate_password_nosymbol == None)):
            parser0.error(
                'either specify the password yourself or generate a password of specified size using --generate_password or --generate_password_nosymbol')
        else:
            if args.generate_password != None:
                if len(args.store_credentials)==3:
                    args.store_credentials[2]=generate_password_func(args.generate_password[0])
                else:
                    args.store_credentials.append(generate_password_func(args.generate_password[0]))
            elif args.generate_password_nosymbol != None:
                if len(args.store_credentials)==3:
                    args.store_credentials[2]=generate_no_symbol_func(args.generate_password_nosymbol[0])
                else:
                    args.store_credentials.append(generate_no_symbol_func(args.generate_password_nosymbol[0]))
            else:
                pass
            
            passphrase0 = getpass()
            if os.path.exists(f'{home}/passkeys/salt') == False:
                salt = os.urandom(16)
                passhash=hashlib.sha256(passphrase0.encode()).hexdigest()
                f = open(f'{home}/passkeys/salt', 'w+')
                f.write(f"{b64encode(salt).decode('utf-8')}\n{passhash}")
                f.close()
            elif os.path.exists(f'{home}/passkeys/salt') == True:
                saltf=open(f'{home}/passkeys/salt').read().split()
                salt=b64decode(saltf[0])
                passhash=saltf[1]
                thispasshash=hashlib.sha256(passphrase0.encode()).hexdigest()                
                if passhash != thispasshash:
                    parser0.error('wrong password, please try again, if you have forgotton your global password you can reset it but all your previously stored passwords will be lost')


            password_to_store=encryptpass(passphrase0, salt, args.store_credentials[2])
            password_to_store=password_to_store.decode()
            username_to_store=encryptpass(passphrase0, salt, args.store_credentials[1])
            username_to_store=username_to_store.decode()

            if os.path.exists(f'{home}/passkeys/passkeys.yml') == False:
                passkeys={args.store_credentials[0]:{'username':username_to_store,'password':password_to_store}}
                yaml.safe_dump(passkeys, open(f'{home}/passkeys/passkeys.yml','w+'))
            elif os.path.exists(f'{home}/passkeys/passkeys.yml'):
                passkeys=yaml.safe_load(open(f'{home}/passkeys/passkeys.yml'))
                passkeys[args.store_credentials[0]]={'username':username_to_store, 'password':password_to_store}
                yaml.safe_dump(passkeys, open(f'{home}/passkeys/passkeys.yml','w+'))


    elif args.retrieve_credentials: 
        if args.generate_password != None or args.generate_password_nosymbol != None:
            parser0.error('--generate_password and --generate_password_nosymbol are only to be used with -st, --store_credentials arguments')

        if os.path.exists(f'{home}/passkeys/passkeys.yml') == False or os.path.exists(f'{home}/passkeys/salt') == False:
        	parser0.error("there is nothing to be retrieved, you haven't stored any credentials,\n or something is wrong with saved global password")

        passphrase0 = getpass()
        saltf=open(f'{home}/passkeys/salt').read().split()
        salt=b64decode(saltf[0])
        passhash=saltf[1]
        thispasshash=hashlib.sha256(passphrase0.encode()).hexdigest()                
        if passhash != thispasshash:
            parser0.error('wrong password, please try again, if you have forgotton your global password you can reset it but all your previously stored passwords will be lost')

        passkeys=yaml.safe_load(open(f'{home}/passkeys/passkeys.yml'))
        servicename=args.retrieve_credentials[0]
        try:
        	encryptedpassword=passkeys[servicename]['password']
        except KeyError:
        	parser0.error('credentials for specified service/website not found')
        encryptedusername=passkeys[servicename]['username']
        username=decryptpass(passphrase0, salt, encryptedusername)
        password_to_print=decryptpass(passphrase0, salt, encryptedpassword)
        print(f'your credentials for {servicename}: ')
        print(f'username: {username.decode()}')
        print('your password has been copied to clipboard')
        pyperclip.copy(password_to_print.decode())

    elif args.list_credentials:
        if args.generate_password != None or args.generate_password_nosymbol != None:
            parser0.error('--generate_password and --generate_password_nosymbol are only to be used with -st, --store_credentials arguments')

        if os.path.exists(f'{home}/passkeys/passkeys.yml') == False or os.path.exists(f'{home}/passkeys/salt') == False:
            parser0.error("there is nothing to be retrieved, you haven't stored any credentials,\n or something is wrong with saved global password")

        passphrase0 = getpass()
        saltf=open(f'{home}/passkeys/salt').read().split()
        salt=b64decode(saltf[0])
        passhash=saltf[1]
        thispasshash=hashlib.sha256(passphrase0.encode()).hexdigest()                
        if passhash != thispasshash:
            parser0.error('wrong password, please try again, if you have forgotton your global password you can reset it but all your previously stored passwords will be lost')

        passkeys=yaml.safe_load(open(f'{home}/passkeys/passkeys.yml'))
        plot_table(passkeys, salt, passphrase0)

    elif args.delete_credentials:
        if args.generate_password != None or args.generate_password_nosymbol != None:
            parser0.error('--generate_password and --generate_password_nosymbol are only to be used with -st, --store_credentials arguments')

        if os.path.exists(f'{home}/passkeys/passkeys.yml') == False or os.path.exists(f'{home}/passkeys/salt') == False:
            parser0.error("there is nothing to be retrieved, you haven't stored any credentials,\n or something is wrong with saved global password")

        passkeys=yaml.safe_load(open(f'{home}/passkeys/passkeys.yml'))
        newpasskeys=delete_credentials(passkeys, args.delete_credentials[0])
        yaml.safe_dump(newpasskeys, open(f'{home}/passkeys/passkeys.yml', 'w+'))

    elif args.change_globalpassword:
        if args.generate_password != None or args.generate_password_nosymbol != None:
            parser0.error('--generate_password and --generate_password_nosymbol are only to be used with -st, --store_credentials arguments')

        if os.path.exists(f'{home}/passkeys/passkeys.yml') == False or os.path.exists(f'{home}/passkeys/salt') == False:
            parser0.error("no existing global paassword to change, you haven't stored any credentials,\n or something is wrong with saved global password")

        passphrase0 = getpass()
        saltf=open(f'{home}/passkeys/salt').read().split()
        salt=b64decode(saltf[0])
        passhash=saltf[1]
        thispasshash=hashlib.sha256(passphrase0.encode()).hexdigest()                
        if passhash != thispasshash:
            parser0.error('wrong password, please try again, if you have forgotton your global password you can reset it but all your previously stored passwords will be lost')        

        newpassphrase = getpass('new global password: ')
        newsalt = os.urandom(16)    
        passkeys=yaml.safe_load(open(f'{home}/passkeys/passkeys.yml'))
        newpasskeys={}
        for i in passkeys.keys():
        	username_decrypted=decryptpass(passphrase0,salt,passkeys[i]['username'])
        	password_decrypted=decryptpass(passphrase0,salt,passkeys[i]['password'])
        	new_username=encryptpass(newpassphrase, newsalt, (username_decrypted).decode())
        	new_password=encryptpass(newpassphrase, newsalt, (password_decrypted).decode())
        	newpasskeys.update({i:{'username':new_username.decode(),'password':new_password.decode()}})
        yaml.safe_dump(newpasskeys, open(f'{home}/passkeys/passkeys.yml','w+'))
        saltb64=b64encode(newsalt).decode('utf-8')
        newsalthash=hashlib.sha256(newpassphrase.encode()).hexdigest()
        open(f'{home}/passkeys/salt','w+').write(f'{saltb64}\n{newsalthash}')


if __name__ == '__main__':
    main()
