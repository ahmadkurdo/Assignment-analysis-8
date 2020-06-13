import re
from time import sleep
import json

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
        with open('data.json', 'w') as f:
            encrypted = self.encryptor.encrypt(self.data)
            json.dump(encrypted, f,indent=2)
            f.close()

    def getAdvisor(self, username):
        try:
            return self.data['advisors'][username]
        except KeyError:
            self.message = 'User does not exist'
            self.error = True

    def registerAdvisor(self, object):
        if self.getAdvisor(object.username):
            self.message = 'Username already exists'
            self.error = True
        else:
            self.data["advisors"][object.username] = object.__dict__
    
    def getSystemAdministrator(self, username):
        try:
            return self.data["systemadministrators"][username]
        except KeyError:
            self.message = 'User does not exist'
            self.error = True
    
    def registerSystemAdministrator(self, object):
        if self.getSystemAdministrator(object.username):
            self.message = 'Username already exists'
            self.error = True
        else:
            self.data["systemadministrators"][object.username] = object.__dict__
    
    def getSuperAdministrator(self, username):
        try:
            return self.data["superadministrators"][username]
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

class Authentication:
    grantAccess = False
    def authenticate(self, username, password):
        pass

class InputHandler:
    emailStatus = False
    passwordStatus = False
    usernameStatus = False
    addressStatus = False
    zipCodeStatus = False
    phoneNumberStatus = False
    fullNameStatus = False
    streetStatus = False
    message = ''
    
    def checkEmail(self,email):
        email = str(email)
        regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        if(re.search(regex,email)):
            self.emailStatus = True  
        else:
            self.message = "You entered an invalid email address. Please try again"
 
    def checkPassword(self,password):
         #to do: Handel \'
        regex_upper = '[A-Z]'
        regex_lower = '[a-z]'
        regex_special = '[~!@#$%^&*_+=.|/?(){}:<>,;`\[\]]'
        regex_digits = '[0-9]'
        
        if(re.search(regex_digits,password) and re.search(regex_special,password) and re.search(regex_lower,password) 
        and re.search(regex_upper,password) and (len(password)>=8 and len(password)<=30)):
            self.passwordStatus = True
        else:
            self.message = '''Invalid password. Please make sure your password contains a combination of at least 
            one lowercase letter, one uppercase letter, one digit, and one special character and has between 8 to 30 characters'''
  
    def checkUsername(self,username):
        #to do: change uppercase to lowercase
        #to do: Handel \
        regex_restricted_characters = '[~!@#$%^&*+=|/?(){}:<>,;`\[\]]'
        if(re.search(regex_restricted_characters,username) or len(username)<5 or len(username)>20 ):
            self.usernameStatus = False
            self.message = '''Invalid username. The username may only contain 
            letters (a-z), numbers (0-9), dashes (-), underscores (_), apostrophes ('), and periods (.) 
            and has to be between 5 to 20 characters'''
        else:
            self.usernameStatus = True
            
    def checkZipCode(self,zipcode):
        #to do: change lowercase to uppercase
        regex_zipcode_pattern = '\d{4}[A-Z]{2}'
        if(re.search(regex_zipcode_pattern,zipcode)):
            self.zipCodeStatus = True
        else:
            self.message = "Invalid zipcode. The zipcode must contain 4 digits and 2 letters"
            self.zipCodeStatus = False
    
    def checkPhoneNumber(self,phoneNumber):
        regex_phone_number_pattern = '[+]31[-]6[-]\d{4}[-]\d{4}'
        if(re.search(regex_phone_number_pattern,phoneNumber)):
            self.phoneNumberStatus = True
        else:
            self.message = "Invalid phone number. The phone number must have the following format: (+31-6-DDDD-DDDD)"
            self.zipCodeStatus = False
    
    def checkFullName(self,fullName):
        #to do: Handel \
        regex_restricted_characters = '[~!@#$%^&*+=|/?(){}:<>,;`\[\]\d]'
        if(re.search(regex_restricted_characters,fullName)):
            self.fullNameStatus = False
            self.message = '''Invalid name. Please make sure that your name does not contain special characters or digit.'''
        else:
            self.fullNameStatus = True
    
    def checkStreet(self,street):
        #to do: Handel \
        regex_restricted_characters = '[~!@#$%^&*+=|/?(){}:<>,;`\[\]]'
        if(re.search(regex_restricted_characters,street)):
            self.streetStatus = False
            self.message = '''Invalid street. Please make sure that your name does not contain special characters.'''
        else:
            self.streetStatus = True
    
    def checkHouseNumber(self,houseNumber):
        #to do: Handel \'
        regex_house_number_pattern = '\d{1,5}[A-Z]{1,2}'
        regex_restricted_characters = '[~!@#$%^&*_+=.|/?(){}:<>,;`\[\]]'
        if(re.search(regex_house_number_pattern,houseNumber) and not re.search(regex_restricted_characters,houseNumber) and len(houseNumber)<= 4):
            self.houseNumberStatus = True
        else:
            self.message = '''Invalid house number. Please make sure thst it contains at least 1 number'''
            self.houseNumberStatus= False

