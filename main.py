from winreg import (
    ConnectRegistry,
    OpenKey,
    KEY_ALL_ACCESS,
    EnumValue,
    QueryInfoKey,
    EnumKey,
    HKEY_LOCAL_MACHINE,
    HKEY_CURRENT_USER,
    HKEY_CLASSES_ROOT,
    HKEY_CURRENT_CONFIG,
    HKEY_USERS
)
import configparser
import os
import argparse
import csv
import datetime
import codecs

config = configparser.ConfigParser()
def cls(): # Clears the cli
    _ = os.system('cls')
def nl(): #Prints /n for cli
    _ = os.system('echo.')
parser = argparse.ArgumentParser(
    prog="Registry Forensics Overview",
    description='''A Tool for overviewing relevant registry information. To view and or export keys and their entries.
Argument structure: Subject Action Filetype(optional) Path(optional)''',
    argument_default=None,
    add_help=True
)
parser.add_argument('Subject',
                    action='store',
                    nargs=1,
                    default='all',
                    choices=['system_info', 'autorun','applications','devices', 'all'],
                    type=str,
                    help='''Subject. Which key lists should the script load.
First argument.''')
parser.add_argument('Action',
                    action='store',
                    nargs=1,
                    default='export',
                    choices=['view', 'export', 'both'],
                    type=str,
                    help='''Action, What should the script do.
View = Displays keys in CMD, Export = Writes keys to file
Second argument.''')
parser.add_argument('Filetype',
                    action='store',
                    nargs='?',
                    default='csv',
                    choices=['txt', 'csv'],
                    type=str,
                    help='''Filetype Choice.
Third argument.
Default: csv''')
parser.add_argument('Path',
                    action='store',
                    nargs='?',
                    default=os.getcwd(),
                    type=str,
                    help='''Path. Which directory should the script export the keys too.
Fourth arguemnt.
Format: "path"
Default: script directory''')
args = parser.parse_args()
Subject = args.Subject
Action = args.Action[0]
Filetype = args.Filetype
Path = args.Path

#global dictionary of keys fetched
key_dic = {}

#main program control. Interperates arguments
def main():
    print("\nDigital Forensics Registry overview")
    if os.path.exists((os.getcwd()+'\\config.ini')) == False:
        config.read_string('''
#[Example Title]
#depth = 0 gets provided entries of the paths. depth= 1 gets the entries of the subkeys of the provided paths
#tag = which argument should the section be part of
#paths = key path. For multiple do <Path1>
#        <path2> 
#        <path3> etc...

[Current Version and Build Info]
depth=0
tag=system_info
paths=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion


[System Enviorment Variables]
depth=0
tag=system_info
paths=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
''')
        with open((os.getcwd()+'\\config.ini'), 'w', encoding='utf8') as conf:
            config.write(conf)
    config.read('config.ini')
    for i in config.sections():
        if Subject == ['all'] or config[i]['tag'] in Subject:
            try:
                get_paths(i)
            except PermissionError:
                print('Access is denies. Run as Admin')
                break
    if Action == 'both' or Action == 'show':
        print_info()
    if Action == 'both' or Action == 'export':
        if Filetype == 'txt':
            export_txt(key_dic,'Reg_Key_Export')
        else:
            export_csv(key_dic,'Reg_Key_Export')
    #for i in config.sections():

    #     if Subject == config[i]['tag']
    # resolve_hive()

    # if Subject == ['system_info'] or Subject == ['all']:
    #     print(f'''\nLoading {sysinf}''')
    #     config.read(sysinf)
    # if Subject == ['autorun'] or Subject == ['all']:
    #     print(f'''\nLoading {autorun}''')
    #     config.read(autorun)
    # resolve_hive()
    # if Action == ['view'] or Action == ['both']:
    #     print_info()
    # if Action == ['export'] or Action == ['both']:
    #     if Filetype == 'txt':
    #         export_txt(key_dic,Subject)
    #     else:
    #         export_csv(key_dic,Subject)
def get_paths(sec):
    paths = config[sec]['paths'].splitlines()
    for i in paths:
        h = i.partition("\\")[0]
        pth = i.strip(h)
        #print(h,pth[1:])
        resolve_hive(h,pth[1:],sec)


#Using, hive and path fetches key info. Gets entries and enumerates them.
def key_info(hive, path:str, ttl):
    values = []
    WIN32_TIME = datetime.datetime(1601, 1, 1)
    if config[ttl]['depth'] == '0':
        with OpenKey(hive, path, 0, KEY_ALL_ACCESS) as key:
            key_info = QueryInfoKey(key)
            mod = WIN32_TIME + datetime.timedelta(microseconds=QueryInfoKey(key)[2] // 10)
            for i in range(key_info[1]):
                values.append(EnumValue(key, i))
            key_dic[ttl] = values, mod.strftime('%m/%d/%Y %H:%M:%S.%f'),path
            return key_dic
    elif config[ttl]['depth'] == '1':
        for skey in get_subkeys(hive,path):
            with OpenKey(hive,skey,0,KEY_ALL_ACCESS) as sub_key:
                sub_key_info = QueryInfoKey(sub_key)
                mod = WIN32_TIME + datetime.timedelta(microseconds=QueryInfoKey(sub_key)[2] // 10)
                for n in range(sub_key_info[1]):
                    values.append(EnumValue(sub_key,n))
                key_dic[ttl] = values, mod.strftime('%m/%d/%Y %H:%M:%S.%f'),skey
        return key_dic
        # with OpenKey(hive, path, 0, KEY_ALL_ACCESS) as key:
        #     key_info = QueryInfoKey(key)
        #     for i in range(key_info[0]):
        #         sub_key_name = EnumKey(key,i)
        #         skey_pth = path+'\\'+sub_key_name
        #         #print(sub_key_name)
        #         print(skey_pth)
        #         with OpenKey(hive,skey_pth,0,KEY_ALL_ACCESS) as sub_key:
        #             sub_key_info = QueryInfoKey(sub_key)
        #             mod = WIN32_TIME + datetime.timedelta(microseconds=QueryInfoKey(sub_key)[2] // 10)
        #             for n in range(sub_key_info[1]):
        #                 values.append(EnumValue(sub_key,n))
        #             key_dic[ttl] = values, mod.strftime('%m/%d/%Y %H:%M:%S.%f'),skey_pth
        #     return key_dic
    else:
        #for nr in range(0,int(config[ttl]['depth'])):
        for skey in get_subkeys(hive, path):
            for sskey in get_subkeys(hive,skey):
                with OpenKey(hive,sskey,0,KEY_ALL_ACCESS) as sub_key:
                    sub_key_info = QueryInfoKey(sub_key)
                    mod = WIN32_TIME + datetime.timedelta(microseconds=QueryInfoKey(sub_key)[2] // 10)
                    for n in range(sub_key_info[1]):
                        values.append(EnumValue(sub_key,n))
                    key_dic[ttl] = values, mod.strftime('%m/%d/%Y %H:%M:%S.%f'),sskey
        return key_dic

def get_subkeys(hive, path):
    skey_pth = []
    with OpenKey(hive, path, 0, KEY_ALL_ACCESS) as key:
        key_info = QueryInfoKey(key)
        for i in range(key_info[0]):
            sub_key_name = EnumKey(key, i)
            skey_pth.append(path + '\\' + sub_key_name)
    return skey_pth

#Takes .ini file config and gets key path and hive from it
def resolve_hive(h,pth,i):
    match h:
        case 'HKEY_LOCAL_MACHINE':
            with ConnectRegistry(None, HKEY_LOCAL_MACHINE) as hive:
                (key_info(hive,pth,i))
        case 'HKEY_CURRENT_USER':
            with ConnectRegistry(None, HKEY_CURRENT_USER) as hive:
                (key_info(hive,pth,i))
        case 'HKEY_CLASSES_ROOT':
            with ConnectRegistry(None, HKEY_CLASSES_ROOT) as hive:
                (key_info(hive, pth, i))
        case 'HKEY_USERS':
            with ConnectRegistry(None, HKEY_USERS) as hive:
                (key_info(hive,pth,i))
        case 'HKEY_CURRENT_CONFIG':
            with ConnectRegistry(None, HKEY_CURRENT_CONFIG) as hive:
                (key_info(hive,pth,i))
    # for i in config.sections():
    #     print(f'''{i} keys...''')
    #     match config[i]['hive']:
    #         case 'HKEY_LOCAL_MACHINE':
    #             with ConnectRegistry(None, HKEY_LOCAL_MACHINE) as hive:
    #                 # key_lst.append(key_enum(hive, config[i]['path'], i))
    #                 (key_enum(hive, config[i]['path'], i))
    #         case 'HKEY_CURRENT_USER':
    #             with ConnectRegistry(None, HKEY_CURRENT_USER) as hive:
    #                 # key_lst.append(key_enum(hive, config[i]['path'], i))
    #                 (key_enum(hive, config[i]['path'], i))
    #         case 'HKEY_CLASSES_ROOT':
    #             with ConnectRegistry(None, HKEY_CLASSES_ROOT) as hive:
    #                 # key_lst.append(key_enum(hive, config[i]['path'], i))
    #                 (key_enum(hive, config[i]['path'], i))
    #         case 'HKEY_USERS':
    #             with ConnectRegistry(None, HKEY_USERS) as hive:
    #                 #key_lst.append(key_enum(hive, config[i]['path'], i))
    #                 (key_enum(hive, config[i]['path'], i))
    #         case 'HKEY_CURRENT_CONFIG':
    #             with ConnectRegistry(None, HKEY_CURRENT_CONFIG) as hive:
    #                 # key_lst.append(key_enum(hive, config[i]['path'], i))
    #                 (key_enum(hive, config[i]['path'], i))
    #     print(f'''Got registry key "{config[i]['path']}"''')
    # #return key_lst

#Prints the dictionary of keys
def print_info():
    #print(key_dic)
    width = ' ' * 32
    blist = ['']
    #nl()
    for n in key_dic:
        print(f'''\n\n{n}\t\tModified: {key_dic[n][1]}\n{'-'*50}''')
        for x in key_dic[n][0]:
            if x[2] == 3:
                try:
                    btos = x[1]
                    string = btos[::2][:btos[::2].find(b'\x00')].decode()
                    if string == '':
                        raise
                    print(x[0], width[:-len(x[0])], string)
                except:
                    print(x[0], width[:-len(x[0])], x[1])
            else:
                print(x[0], width[:-len(x[0])],x[1])
            #print(x[0], width[:-len(x[0])], x[1])

#Exports the dictionary of keys to csv
def export_csv(exp_dic,ttl):
    n = 0
    fname = namecheck('.csv',ttl)
    with open(fname, 'w',encoding="utf8", newline='') as file:
        writer = csv.writer(file, delimiter=',')
        for key in exp_dic:
            n += 1
            if n != 1:
                writer.writerow(['', '', ''])
            writer.writerow([key, None, (exp_dic[key][1])])
            for x in exp_dic[key][0]:
                writer.writerow(x)
    print(f'''Done exporting keys to "{fname}"''')

#Exports the dictionary of keys to txt
def export_txt(exp_dic,ttl):
    n = 0
    fname = namecheck('.txt', ttl)
    with open(fname, 'w',encoding="utf8",newline='') as file:
        for key in exp_dic:
            n += 1
            if n != 1:
                file.write("\n")
            file.write(f'''{key},{(exp_dic[key][1])}\n''')
            for x in exp_dic[key][0]:
                file.write(f'''{str(x[0])},{str(x[1])},{str(x[2])}''')
                file.writelines('\n')
    print(f'''Done exporting keys to "{fname}"''')

#Function to check if file with same name already exists and resolve issues
def namecheck(ftype,ttl):
    n = 0
    time = datetime.date.today().strftime("%m-%d-%Y")
    fname = f'''{Path}\{ttl}_{time}'''
    while os.path.exists((fname+ftype)) == True:
        n +=1
        if n == 1:
            fname = fname + f'''_{n:02}'''
        else:
            fname = f'''{Path}\{ttl}_{time}'''
            fname = fname + f'''_{n:02}'''
    return fname+ftype


if __name__ == '__main__':
    main()
