import re
from time import sleep
import sys
import os
import json
import ast
import time
import socket

class host:
    attempts = 0
    name = None

    def getHost(self):
        return self.name
    
    def incrementAttempts(self):
        attempts += 1
    
    def hasReachedMaximumAttempts(self):
        if self.attempts >= 5:
            return True
    
    def setAttempts(self,attempts):
        self.attempts = attempts    

class User:
    userName = None
    password = None

class superAdministrator(User):
    def __init__(self,username,password):
        self.username = username
        self.password = password
    
    def createSystemAdministrator(self,username,password):
        systemAdministrator = SystemAdministrator(username,password)
        return systemAdministrator

class SystemAdministrator(User):
    def __init__(self,username,password):
        self.username = username
        self.password = password
    
    def createAdvisor(self,username,password):
        advisor = Advisor(username,password)
        return advisor
    
    def createClient(self,fullName,zipcode,street,houseNumber,email,phoneNumber,city):
        client = Client(fullName,zipcode,street,houseNumber,email,phoneNumber,city)
        return client
   
class Advisor(User):
    def __init__(self,username,password):
        self.username = username
        self.password = password

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

class Encryptor:
    key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    def encrypt(self, plaintext):
        result = ''
        for l in plaintext:
            try:
                i = (self.key.index(l) + 5) % 62
                result += self.key[i]
            except ValueError:
                result += l
        return result

    def decrypt(self,ciphertext):
        result = ''
        for l in ciphertext:
            try:
                i = (self.key.index(l) - 5) % 62
                result += self.key[i]
            except ValueError:
                result += l
        return result

class dataBase:
    error = False
    data = None
    grantAccess = False
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
    
    def refresh(self):
        self.terminate()
        self.load()

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
            self.message = 'Username already exists. You will be redirected to the main screen'
            self.error = True
        else:
            self.data["advisors"][object.username] = object.__dict__
            self.message = 'The new advisor is successfully registered'
            self.error = False
    
    def getSystemAdministrator(self, username):
        try:
            return self.data["systemadministrators"][username]
        except KeyError:
            self.message = 'User does not exist'
            self.error = True
    
    def registerSystemAdministrator(self, object):
        if self.exists(object):
            self.message = 'Username already exists. You will be redirected to the main screen'
            self.error = True
        else:
            self.data["systemadministrators"][object.username] = object.__dict__
            self.message = 'The new system administrator is successfully registered'
            self.error = False
    
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
            self.data["clients"][object.email] = object.__dict__
            self.error = False
    
    def getClient(self, email):
        try:
            return self.data["clients"][email]
        except KeyError:
            self.message = 'Email does not exist'
            self.error = True
    
    def getAll(self, userType):
        return self.data[userType]
    
    def login(self, username, password):
        if self.getSuperAdministrator(username):
            superAdmin = self.getSuperAdministrator(username)
            if superAdmin['password'] == password:
                logedInsuperAdmin = superAdministrator(username,password)
                self.grantAccess = True
                self.error = False
                self.message = 'Access granted'
                return logedInsuperAdmin
            
        if self.getSystemAdministrator(username):
            systemAdmin = self.getSystemAdministrator(username)
            if systemAdmin['password'] == password:
                logedInsystemAdmin = SystemAdministrator(username,password)
                self.grantAccess = True
                self.error = False
                self.message = 'Access granted'
                return logedInsystemAdmin

        if self.getAdvisor(username):
            advisor = self.getAdvisor(username)
            if advisor['password'] == password:
                logedInAdvisor = Advisor(username,password)
                self.grantAccess = True
                self.error = False
                self.message = 'Access granted'
                return logedInAdvisor
        print('Im here')
        self.grantAccess = False
        self.error = True
        self.message = 'Authorization failed. Wrong username or password.\nToo many attempts will result in a ban'

class Formatter:
    def capitalize(self,text):
        return text.capitalize()

    def makeLowerCase(self,text):
        return text.lower()

    def makeUpperCase(self,text):
        return text.upper()

class InputHandler:
    formatter = Formatter()
    error = None
    message = ''
    cities = ['Amsterdam','Almere','Vlaardingen','Nijmegen',
            'Zutphen','Apeldoorn','Rotterdam','Schiedam','Zwolle','Delft']
    
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
        if(re.search(regex_restricted_characters,fullName) or len(fullName)< 5 or len(fullName)>25):
            self.error = True
            self.message = '''Invalid name. Please make sure that your name does not contain\nspecial characters or digits and is between 5 to 25 characters'''
        else:
            self.error = False
    
    def checkStreet(self,street):
        #to do: Handel \
        regex_restricted_characters = '[~!@#$%^&*+=|/?(){}:<>,;`\[\]]'
        if(re.search(regex_restricted_characters,street)):
            self.error = True
            self.message = '''Invalid street. Please make sure that the street name does not contain special characters.'''
        else:
            self.error = False
    
    def checkHouseNumber(self,houseNumber):
        #check not working it must have a letter.
        #to do: Handel \'
        regex_house_number_pattern = '\d{1,5}[A-Z]{1,2}'
        regex_restricted_characters = '[~!@#$%^&*_+=.|/?(){}:<>,;`\[\]]'
        if(re.search(regex_house_number_pattern,houseNumber) and not re.search(regex_restricted_characters,houseNumber) and len(houseNumber)<= 4):
            self.error = False
        else:
            self.message = '''Invalid house number. Please make sure that it contains at least 1 number'''
            self.error = True
    
    def checkCity(self, city):
        if city in self.cities:
            self.error = False
        else:
            self.error = True
            self.message = "Invalid city.\n We don't provide a service yet in the entered city.\n Cities where we provide services are:\nAmsterdam, Almere, Vlaardingen, Nijmegen', Zutphen, Apeldoorn, Rotterdam, Schiedam, Zwolle, Delft"

class App:
    quitScreen = False
    loginScreen = False
    retrieveSystemAdminscreen = False
    allSystemAdminsScreen = False
    allClientsScreen = False
    allAdvisorsScreen = False
    superAdminScreen = False
    systemAdminScreen = False
    registerAdvisorScreen = False
    registerSystemAdminscreen = False
    registerClientScreen = False
    userCredentials = None
    registeredUserObject = None
    inputHandler = InputHandler()
    formatter = Formatter()

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
    
    def displayLoadScreen(self):
        os.system('clear')
        self.slowprint("\t\t\tLoading all the data")
        self.fastPrint("--------------------------------------------------------------------------------")

    def displayTitleBar(self, title):
        # Clears the terminal screen, and displays a title bar.
        time.sleep(0.5)
        os.system('clear')
        print("\t**********************************************")
        print("\t***  {}  ***".format(str(title)))
        print("\t**********************************************")
        print('\n')
        
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

            password = input("Enter your password: ")
            self.inputHandler.checkPassword(password)
        
            if self.inputHandler.error:
                self.slowprint('Incorrect username or password.')
                self.slowprint("\n Please try again \n")
                continue
            
            self.userCredentials = {}
            self.userCredentials['username'] = self.formatter.makeLowerCase(username)
            self.userCredentials['password'] = str(password)
            break
    
    def displayInformationScreen(self,title,message):
        self.displayTitleBar('  {}  '.format(title))
        self.slowprint(message)
        time.sleep(5)
    
    def displaySuperAdminScreen(self,superAdminObject):
        while True:
            self.displayTitleBar("\tSuper Administrator - {}".format(str(superAdminObject.username)))
            print("\n[1] Register a system administrator.")
            print("[2] Display system administrators.")
            print("[q] Quit.")
            choice = input("What would you like to do? ")
            if str(choice) == '1':
                self.registerSystemAdminscreen = True
                break
            elif str(choice) == '2':
                self.allSystemAdminsScreen = True
                break
            elif str(choice) == 'q':
                self.quitScreen = True
                break
            else:
                self.slowprint("\nI didn't understand that choice. Please try again\n")
                os.system('clear')
         
    def displayRegisterationScreen(self, userObject, title, userRole):
        while True:     
            self.displayTitleBar('Register a new {}'.format(userRole))
            print('\n')
            username = input("Enter a username for the new {}: ".format(userRole))
            self.inputHandler.checkUsername(username)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\nPlease try again \n")
                continue

            password = input("Enter a password for the new {}: ".format(userRole))
            self.inputHandler.checkPassword(password)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\nPlease try again \n")
                continue
            
            password2 = input("Confirm the password for the new {}: ".format(userRole))
            self.inputHandler.checkPassword(password)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\nPlease try again \n")
                continue
            
            if password != password2:
                self.slowprint("\nPasswords did not match. Please try again \n")
                continue
            
            if isinstance(userObject,superAdministrator):
                self.registeredUserObject = userObject.createSystemAdministrator(self.formatter.makeLowerCase(username),password)
                self.slowprint("\nProvided credentials for the system administrator were corrected.\n")
            
            if isinstance(userObject,SystemAdministrator):
                self.registeredUserObject = userObject.createAdvisor(self.formatter.makeLowerCase(username),password)
                self.slowprint("\nProvided credentials for the advisor were corrected.\n")
            
            self.slowprint("\t\t\tDoing some system checks")
            self.fastPrint("--------------------------------------------------------------------------------")
            break
    
    def displayClientRegisterationScreen(self,userObject):
        while True:     
            self.displayTitleBar('         Register a new client      ')
            print('\n')
            fullname = input("Enter the full name of the new client: ")
            self.inputHandler.checkFullName(fullname)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\nPlease try again \n")
                continue
            
            zipcode = input("Enter the zipcode of the new client: ")
            self.inputHandler.checkZipCode(zipcode)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\nPlease try again \n")
                continue
            
            street = input("Enter the street of the new client: ")
            self.inputHandler.checkStreet(street)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\nPlease try again \n")
                continue
            
            housenumber = input("Enter the house number of the new client: ")
            self.inputHandler.checkHouseNumber(housenumber)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\nPlease try again \n")
                continue
            
            email = input("Enter the email of the new client: ")
            self.inputHandler.checkEmail(email)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\nPlease try again \n")
                continue
            
            phonenumber = input("Enter the phone number of the new client: ")
            self.inputHandler.checkPhoneNumber(phonenumber)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\nPlease try again \n")
                continue
            
            city = input("Enter the city of the new client: ")
            city =  self.formatter.makeLowerCase(city)  
            city = self.formatter.capitalize(city)
            self.inputHandler.checkCity(city)
            if self.inputHandler.error:
                self.slowprint(self.inputHandler.message)
                self.slowprint("\nPlease try again \n")
                continue
            self.registeredUserObject = userObject.createClient(fullname, zipcode,street,housenumber,email,phonenumber,city)
            self.slowprint("\nClient successfully registered\n")
            break
    
    def displayAllUsersByType(self, userDict, title, userRole):
        self.displayTitleBar('         {}         '.format(title))
        for user in userDict.values():
            print('Name: ' + str(user['username']) + '\n')
            print('Role: ' + '{}'.format(userRole))
            self.fastPrint("--------------------------")
        time.sleep(5)
    
    def displayAllClients(self, userDict):
        self.displayTitleBar('         All clients overview         ')
        for user in userDict.values():
            print('Name: ' + str(user['fullName']))
            print('Email: ' + str(user['email']))
            print('Street: ' + str(user['street']))
            print('House number: ' + str(user['houseNumber']))
            print('Zipcode: ' + str(user['zipCode']))
            print('City: ' + str(user['city']))
            self.fastPrint("--------------------------")
        time.sleep(5)
    
    def displaySystemAdminScreen(self, systemAdminObject):
        while True:
            self.displayTitleBar("System administrator - {}".format(str(systemAdminObject.username)))
            print("\n[1] Register a advisor.")
            print("[2] Register a client.")
            print("[3] Display all clients.")
            print("[4] Display all advisors.")
            print("[q] Quit.")
            
            choice = input("What would you like to do? ")
            if str(choice) == '1':
                self.registerAdvisorScreen = True
                break
            elif str(choice) == '2':
                self.registerClientScreen = True
                break
            elif str(choice) == '3':
                self.allClientsScreen = True
                break
            elif str(choice) == '4':
                self.allAdvisorsScreen = True
                break
            elif str(choice) == 'q':
                self.quitScreen = True
                break
            else:
                self.slowprint("\nI didn't understand that choice. Please try again\n")
                os.system('clear')
    
    def decideScreen(self,userObject):
            if isinstance(userObject,superAdministrator):
                self.superAdminScreen = True
     
            if isinstance(userObject,SystemAdministrator):
                self.systemAdminScreen = True
            
            if isinstance(userObject,Advisor):
                self.advisorScreen = True
   
#Main application
if __name__ == "__main__":
    while True:

        app = App()
        db = dataBase()
        db.load()
        db.terminate()
        app.displayLoadScreen()
        formatter = Formatter()
        app.dislpayStartScreen()
        logedInObject = None
        
        if app.quitScreen:
            app.displayInformationScreen('\t\tTerminating       \t', 'We hope to see you soon again ;)')
            time.sleep(1)
            os.system('clear')
            sys.exit()
        
        while True:    
            if app.loginScreen:
                app.displayLoginScreen()
                logedInObject = db.login(app.userCredentials['username'],app.userCredentials['password'])
                if db.error:
                    app.displayInformationScreen('\t\tWARNING\t\t', db.message)
                    
                if db.grantAccess:
                    app.decideScreen(logedInObject)
                    app.displayInformationScreen('\t\tLogin successful\t', db.message)
                    app.loginScreen = False

            elif app.superAdminScreen:
                app.displaySuperAdminScreen(logedInObject)
                app.superAdminScreen = False
            
            elif app.allSystemAdminsScreen:
                systemAdmins = db.getAll('systemadministrators')
                app.displayAllUsersByType(systemAdmins,'All system administrators','system administrator')
                app.allSystemAdminsScreen = False
                app.superAdminScreen = True
            
            elif app.registerSystemAdminscreen:
                app.displayRegisterationScreen(logedInObject,'System administrator registration','system administrator')
                createdObject = app.registeredUserObject
                db.registerSystemAdministrator(createdObject)
                if db.error:
                    app.displayInformationScreen('Registration error', db.message)
                else:
                    print('Im in registered')
                    app.displayInformationScreen('Registration successful',db.message)
                    db.refresh()
                app.registerSystemAdminscreen = False
                app.superAdminScreen = True
            
            elif app.systemAdminScreen:
                app.displaySystemAdminScreen(logedInObject)
                app.systemAdminScreen = False
            
            elif app.allAdvisorsScreen:
                advisors = db.getAll('advisors')
                app.displayAllUsersByType(advisors,'All adivors','advisor')
                app.systemAdminScreen = True
                app.allAdvisorsScreen= False
            
            elif app.allClientsScreen:
                clients = db.getAll('clients')
                app.displayAllClients(clients)
                app.allClientsScreen = False
                app.systemAdminScreen = True
            
            elif app.registerClientScreen:
                app.displayClientRegisterationScreen(logedInObject)
                createdObject = app.registeredUserObject
                db.registerClient(createdObject)
                if db.error:
                    app.displayInformationScreen('Registration error', db.message)
                else:
                    app.displayInformationScreen('Registration successful',db.message)
                    db.refresh()
                app.registerClientScreen = False
                app.systemAdminScreen = True
  
            elif app.registerAdvisorScreen:
                app.displayRegisterationScreen(logedInObject,'Advisor registration','advisor')
                createdObject = app.registeredUserObject
                db.registerAdvisor(createdObject)
                if db.error:
                    app.displayInformationScreen('Registration error', db.message)
                else:
                    app.displayInformationScreen('Registration successful',db.message)
                    db.refresh()
                app.registerAdvisorScreen = False
                app.systemAdminScreen = True
 
            elif app.quitScreen:
                app.displayInformationScreen('\t\tLogging out    \t', 'We hope to see you soon again ;)')
                db.terminate()
                time.sleep(2)
                break



        
    

