# Passman
Passman is a simple commandline password manager that stores passwords in encrypted form, you only have to remember one global password to retrieve all your passwords to services/websites you use, it also can generate passwords with or without symbols of given size.

## installation
first download the program from release section, (not the source code) after downloading the tar.gz file do this.
```
pip install /path/to/passman-0.1.tar.gz
```
it will install all the dependencies automatically.<br>
**NOTE:** python 3.7 or greater is required

after successfull installation it should show the following screen in terminal after you execute passman from terminal with passman command.<br>
<Br>
![noargument](noargument.png)

## Features
* store passwords in encrypted form
* lets you display all stored passwords in a pretty table inside ascii
* generate cryptographically secure passwords with or without symbols

## store credentials
```
-st or --store_credentials
```
this option lets you store passwords in encrpyted form, the first time you try to store a password it will still ask you for a global password, the password entered on that time will be assigned as your global password, so remember that.
```
passman -st [website/service] [login/username] [password]
```
or 
```
passman -st [website] [login/username] -gp [size]
```
or
```
passman -st [website] [login/username] -gpn [size]
```
### examples
```
passman -st test test@login.com 123456
```
or
```
passman -st test test@login.com -gp 12
```
the above example will generate a password and store that in to your stored passwords file. if you mention a password and also apply the argument of -gp/-gpn or --generate_password/generate_password_nosymbol the mentioned password will be overwritten by the generated one and that will be stored in password file.

### retrieve credentials
```
-rt or --retrieve_credentials
```
you can retrieve password username etc by this option. this option will print the username on terminal but will copy the password to clipboard without printing it on terminal for security
```
passman -rt [website/service]
```
### example
```
passman -rt test
```

### list credentials
this option lets you print all stored passwords in pretty grid table on terminal
```
-l or --list_credentials
```
```
passman -l
```

### change global password
this option lets you change the global password that you entered the first time you used the program to store a password/credential.<Br>
**NOTE:** you must remember the old global password to change it, if you have forgotten it, all your old passwords will be useless since all passwords are encrypted with that global password and salts

```
-cgp or --change_globalpassword
```
```
passman -cgp
```
**NOTE:** all arguments prompt you with a global password, that won't print as you type like sudo does in linux