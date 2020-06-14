import re
from time import sleep
import sys
import os
import json
import ast
import time

class User:
    userName = None
    password = None

class superAdministrator(User):
    
    def __init__(self,username,password):
        self.username = username
        self.password = password
        self.role = 1
    
    def createSystemAdministrator(self,username,password):
        systemAdministrator = SystemAdministrator(username,password)
        return systemAdministrator

class SystemAdministrator(User):
    
    def __init__(self,username,password):
        self.username = username
        self.password = password
        self.role = 2
    
    def createAdvisor(self,username,password):
        advisor = Advisor(username,password)
        return advisor
    
    def createClients(self,fullName,zipcode,street,houseNumber,email,phoneNumber,city):
        client = Client(fullName,zipcode,street,houseNumber,email,phoneNumber,city)
        return client
   
class Advisor(User):
     
    def __init__(self,username,password):
        self.username = username
        self.password = password
        self.role = 3

class Client: 
    fullName = None
    zipCode = None
    street = None
    houseNumber = None
    email = None
    phoneNumber = None
    city = None
    
    def __init__(self,fullName,zipCode,street,houseNumber,email,phoneNumber,city):
        self.fullName = fullName
        self.zipCode = zipCode
        self.street = street
        self.houseNumber = houseNumber
        self.email = email
        self.phoneNumber = phoneNumber
        self.city = city
        self.role = 4

class Encryptor:
    key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    def encrypt(self, plaintext):
        """Encrypt the string and return the ciphertext"""
        result = ''

        for l in plaintext:
            try:
                i = (self.key.index(l) + 5) % 52
                result += self.key[i]
            except ValueError:
                result += l
        return result

    def decrypt(self,ciphertext):
        """Decrypt the string and return the plaintext"""
        result = ''
        for l in ciphertext:
            try:
                i = (self.key.index(l) - 5) % 52
                result += self.key[i]
            except ValueError:
                result += l
        return result

    
class dataBase:
    error = False
    data = None
    message = ''
    encryptor = Encryptor()

    def load(self):
        data = ''
        with open('data.json','r') as f:
            for line in f:
                for letter in line:
                    data += letter
            f.close()
        decrypted = self.encryptor.decrypt(data)
        self.data = json.loads(decrypted)

    def terminate(self):
        data = eval(json.dumps(self.data))
        with open('data.json', 'w') as f:
            encrypted = self.encryptor.encrypt(str(data))
            encrypted_dict = ast.literal_eval(encrypted) 
            json.dump(encrypted_dict, f,indent=2)
            f.close()

    def exists(self,object):
        if (self.getAdvisor(object.username) or self.getSystemAdministrator(object.username) or self.getSuperAdministrator(object.username)):
            return True
    
    def getAdvisor(self, username):
        try:
            return self.data['advisors'][username]
        except KeyError:
            self.message = 'User does not exist'
            self.error = True

    def registerAdvisor(self, object):
        if self.exists(object):
            self.message = 'Username already exists'
            self.error = True
            print("Username is already taken")
        else:
            self.data["advisors"][object.username] = object.__dict__
    
    def getSystemAdministrator(self, username):
        try:
            return self.data["systemadministrators"][username]
        except KeyError:
            self.message = 'User does not exist'
            self.error = True
    
    def registerSystemAdministrator(self, object):
        if self.exists(object):
            self.message = 'Username already exists'
            self.error = True
        else:
            self.data["systemadministrators"][object.username] = object.__dict__
    
    def getSuperAdministrator(self, username):
        try:
            return self.data["supermadministrators"][username]
        except KeyError:
            self.message = 'User does not exist'
            self.error = True
    
    def registerClient(self, object):
        if self.getClient(object.email):
            self.message = 'User with this email already exists'
            self.error = True
        else:
            self.data["advisors"][object.username] = object.__dict__
    
    def getClient(self, email):
        try:
            return self.data["clients"][email]
        except KeyError:
            self.message = 'Email does not exist'
            self.error = True
    
    def getAll(self, userType):
        return self.data[userType]

class Authentication:
    grantAccess = False
    def authenticate(self, username, password):
        pass

class InputHandler:
    error = None
    message = ''
    
    def checkEmail(self,email):
        email = str(email)
        regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        if(re.search(regex,email)):
            self.error = False  
        else:
            self.message = "You entered an invalid email address. Please try again"
            self.error = True
 
    def checkPassword(self,password):
         #to do: Handel \'
        regex_upper = '[A-Z]'
        regex_lower = '[a-z]'
        regex_special = '[~!@#$%^&*_+=.|/?(){}:<>,;`\[\]]'
        regex_digits = '[0-9]'
        
        if(re.search(regex_digits,password) and re.search(regex_special,password) and re.search(regex_lower,password) 
        and re.search(regex_upper,password) and (len(password)>=8 and len(password)<=30)):
            self.error = False
        else:
            self.message = 'Invalid password.\n\n Please make sure your password contains a combination of at least\n one lowercase letter, one uppercase letter, one digit, and one special\n character and has between 8 to 30 characters'
            self.error = True
  
    def checkUsername(self,username):
        #to do: change uppercase to lowercase
        #to do: Handel \
        regex_restricted_characters = '[~!@#$%^&*+=|/?(){}:<>,;`\[\]]'
        if(re.search(regex_restricted_characters,username) or len(username)<5 or len(username)>20 ):
            self.error = True
            self.message = "Invalid username.\nThe username may only contain letters (a-z), numbers (0-9),\ndashes (-), underscores (_), apostrophes ('), and periods (.)\nand has to be between 5 to 20 characters"
        else:
            self.error = False
            
    def checkZipCode(self,zipcode):
        #to do: change lowercase to uppercase
        regex_zipcode_pattern = '\d{4}[A-Z]{2}'
        if(re.search(regex_zipcode_pattern,zipcode)):
            self.error = False
        else:
            self.message = "Invalid zipcode. The zipcode must contain 4 digits and 2 letters"
            self.error = True
    
    def checkPhoneNumber(self,phoneNumber):
        regex_phone_number_pattern = '[+]31[-]6[-]\d{4}[-]\d{4}'
        if(re.search(regex_phone_number_pattern,phoneNumber)):
            self.error = False
        else:
            self.message = "Invalid phone number. The phone number must have the following format: (+31-6-DDDD-DDDD)"
            self.error = True
    
    def checkFullName(self,fullName):
        #to do: Handel \
        regex_restricted_characters = '[~!@#$%^&*+=|/?(){}:<>,;`\[\]\d]'
        if(re.search(regex_restricted_characters,fullName)):
            self.error = False
            self.message = '''Invalid name. Please make sure that your name does not contain special characters or digit.'''
        else:
            self.error = True
    
    def checkStreet(self,street):
        #to do: Handel \
        regex_restricted_characters = '[~!@#$%^&*+=|/?(){}:<>,;`\[\]]'
        if(re.search(regex_restricted_characters,street)):
            self.error = False
            self.message = '''Invalid street. Please make sure that your name does not contain special characters.'''
        else:
            self.error = True
    
    def checkHouseNumber(self,houseNumber):
        #to do: Handel \'
        regex_house_number_pattern = '\d{1,5}[A-Z]{1,2}'
        regex_restricted_characters = '[~!@#$%^&*_+=.|/?(){}:<>,;`\[\]]'
        if(re.search(regex_house_number_pattern,houseNumber) and not re.search(regex_restricted_characters,houseNumber) and len(houseNumber)<= 4):
            self.error = False
        else:
            self.message = '''Invalid house number. Please make sure that it contains at least 1 number'''
            self.error = True

class App:
    quitScreen = False
    loginScreen = False
    retrieveSystemAdminscreen = False
    registerSystemAdminscreen = False
    userCredentials = {}
    registeredUserObject = None
    inputHandler = InputHandler()

    def slowprint(self,s):
        for c in s + '\n':
            sys.stdout.write(c)
            sys.stdout.flush()
            time.sleep(0.08)
    
    def fastPrint(self,s):
        for c in s + '\n':
            sys.stdout.write(c)
            sys.stdout.flush()
            time.sleep(0.05)

    def displayTitleBar(self, title):
        # Clears the terminal screen, and displays a title bar.
        time.sleep(0.5)
        os.system('clear')
        print("\t**********************************************")
        print("\t***  {}  ***".format(str(title)))
        print("\t**********************************************")
        
    def dislpayStartScreen(self):
        while True:
            self.displayTitleBar('Welcome to the construction company')
            print("\n[1] Login.")
            print("[q] Quit.")
            
            choice = input("What would you like to do? ")
            if choice == '1':
                self.loginScreen = True
                break
            elif choice == 'q':
                self.quitScreen = True
                break
            else:
                self.slowprint("\nI didn't understand that choice. Please try again\n")
                os.system('clear')
    
    def displayLoginScreen(self):
        while True:     
            
            self.displayTitleBar('Please provide your login credentials')
            print('\n')
            username = input("Enter your username: ")
            self.inputHandler.checkUsername(username)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\n Please try again \n")
                continue

            password = input("Enter your password: ")
            self.inputHandler.checkPassword(password)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\n Please try again \n")
                continue

            self.userCredentials['username'] = str(username)
            self.userCredentials['password'] = str(password)
            break
    
    def displaySuperAdminScreen(self,superAdminObject):
        while True:
            self.displayTitleBar("Super Administrator - {}".format(str(superAdminObject.username)))
            print("\n[1] Register a system administrator.")
            print("[2] Display system administrators.")
            print("[q] Quit.")
            
            choice = input("What would you like to do? ")
            if str(choice) == '1':
                self.registerSystemAdminscreen = True
                break
            elif str(choice) == '2':
                self.retrieveSystemAdminscreen = True
                break
            elif str(choice) == 'q':
                self.quitScreen = True
                break
            else:
                self.slowprint("\nI didn't understand that choice. Please try again\n")
                os.system('clear')
        
        
    def displayRegisterSystemAdminScreen(self, superAdminObject):
        while True:     
            self.displayTitleBar('Register a new system administrator')
            print('\n')
            username = input("Enter a username for the new system administrator: ")
            self.inputHandler.checkUsername(username)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\n Please try again \n")
                continue

            password = input("Enter a password for the new system administrator: ")
            self.inputHandler.checkPassword(password)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\n Please try again \n")
                continue
            
            password2 = input("Confirm the password for the new system administrator: ")
            self.inputHandler.checkPassword(password)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\n Please try again \n")
                continue
            
            if password != password2:
                self.slowprint("\nPasswords did not match. Please try again \n")
                continue
            
            self.registeredUserObject = superAdminObject.createSystemAdministrator(username,password)
            self.slowprint("\nSystem administrator successfully registered\n")
            break
    
    def displayAllSystemAdmins(self, systemAdminDict):
        for systemAdmin in systemAdminDict.values():
            print('Name: ' + str(systemAdmin['username']) + '\n')
            print('Role: ' + 'System administrator')
            x.fastPrint("--------------------------")

    def resetScreen(self):
        self.quitScreen = False
        self.loginScreen = False
        self.userCredentials = {}


if __name__ == "__main__":
    y = superAdministrator('Ahmed', 'test4321')
    x = App()
    db =dataBase()
    db.load()
    systemAdmins = db.getAll("systemadministrators")
    x.displayAllSystemAdmins(systemAdmins)

        
    db.terminate()
    

