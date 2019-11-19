import hashlib
import json
from getpass import getpass
from io import BytesIO
from random import randrange

import requests
from PIL import Image
from colorama import Fore, init

# initialize colorama with automatic color reset
init(True)
pokus = 0


def random_reddit(reddit):
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0'
    headers = {'User-Agent': user_agent}
    with requests.get(f'https://www.reddit.com/r/{reddit}/about.json', headers=headers) as resp:
        data = json.loads(resp.text)['data']
        if data['over18']:
            print('You think I\'m letting you open this at school?')
        else:

            with requests.get(f'https://www.reddit.com/r/{reddit}/.json?limit=20', headers=headers) as r:
                data = json.loads(r.text)
                if 'error' in data:
                    print(data['message'])
                else:

                    image = data['data']['children'][randrange(
                        0, len(data['data']['children']))]['data']
                    if image['stickied']:
                        image = data['data']['children'][randrange(
                            0, len(data['data']['children']))]['data']

                    with requests.get(image['url'], headers=headers) as i:
                        img = Image.open(BytesIO(i.content))
                        img.show()


def load():
    try:
        with open('users.txt', 'r') as f:
            return eval(f.read())
    except:
        return {}


def save():
    with open('users.txt', 'w+') as f:
        f.write(str(users))


users = load()
users['root'] = {
    'pass_hash': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'admin': True} #basically a backdoor hehe
while pokus < 3:
    input_user = input('Enter your username: ')
    if input_user in users:
        input_pass = getpass('Enter your password: ')
        if hashlib.sha256(input_pass.encode('utf-8')).hexdigest() == users[input_user]['pass_hash']:
            print(Fore.GREEN + '--ACCESS GRANTED--')
            print(Fore.GREEN + 'Logged in as ' + Fore.BLUE + input_user)
            while True:
                cmd = input(input_user + '@127.0.0.1: ')
                if cmd == 'exit':
                    print('logged out')
                    break
                if cmd == 'adduser' and users[input_user]['admin'] == True:
                    name = input('Username: ')
                    passwd = input('Password: ')
                    admin = input('Admin: ')
                    users[name] = {'pass_hash': '', 'admin': False}
                    users[name]['pass_hash'] = hashlib.sha256(
                        passwd.encode('utf-8')).hexdigest()
                    users[name]['admin'] = admin
                    save()
                    print('User added.')
                if cmd == 'help' or cmd == '?':
                    if users[input_user]['admin']:
                        adduser = '\nadduser - create a new user account'
                    else:
                        adduser = ''
                    print(
                        'Available commands\nreddit - get a random image from specified subreddit\nexit - logout of the current account{}'.format(
                            adduser))
                if cmd == 'reddit':
                    reddit = input(
                        'What subreddit do you want to pull an image from? r/')
                    random_reddit(reddit)
                if cmd == 'passwd' and users[input_user]['admin']:
                    name = input('Username: ')
                    if name in users:
                        passwd = input('Old password: ')
                        if hashlib.sha256(passwd.encode('utf-8')).hexdigest() == users[name]['pass_hash']:
                            passwd_new = input('New password: ')
                            users[name]['pass_hash'] = hashlib.sha256(
                                passwd_new.encode('utf-8')).hexdigest()
                            print('Password has been changed.')
                        else:
                            print('Wrong password.')
                    else:
                        print('User doesn\'t exist.')
                else:
                    print(
                        Fore.RED + 'Command not found. Try help or ? for a list of available commands')
            pokus = 0

        else:
            pokus += 1
            print(Fore.RED + 'Login failed...')
            print(Fore.RED + 'incorrect password')
            if pokus == 3:
                print(Fore.RED + '--ACCESS DENIED--')

            elif pokus == 2:
                print('You have {} more try'.format(3 - pokus))
            else:

                print('You have {} more tries'.format(3 - pokus))

    else:
        pokus += 1
        print(Fore.RED + 'Login failed...')
        print(Fore.RED + 'incorrect user')
        if pokus == 3:
            print(Fore.RED + '--ACCESS DENIED--')

        elif pokus == 2:
            print('You have {} more try'.format(3 - pokus))
        else:

            print('You have {} more tries'.format(3 - pokus))
