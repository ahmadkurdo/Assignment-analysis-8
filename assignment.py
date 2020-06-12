import os
import re
from time import sleep

class User:
    userName = None
    password = None


class SystemAdministrator(User):
    # SystemAdministrator can only be made by SuperAdministrators
    pass

class Advisor(User):
    # Advisors can only be made by SystemAdministrators
    pass

class Encryptor:
    #use Caesar sipher
    def encrypt(self,message):
         #should encrypt the message the txt file
         pass
    def decrypt(self,message):
        #should decrypt message from the txt file
        pass

class client:
    #Full Name − Address:
    #▪ Street and House number
    #▪ City (system should generate a list of 10 city names of your choice predefined in the system)
    #− Mobile Phone (+31-6-DDDD-DDDD)
    pass

class dataBase:
    clients = {}
    systemAdministrators = {}
    advisors = {}
    hosts = {}

    def load(self):
        #loads everything from the txt file into the attributes
        pass
    def save(self):
        # saves new data into the attributes
        pass
    def terminate(self):
        # saves everything back to the txt file when the application terminates
        pass

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
        regex_restricted_characters = '[~!@#$%^&*+=|/?(){}:<>,;`\[\]]'
        if(re.search(regex_restricted_characters,username) or len(username)<5 or len(username)>20 ):
            self.usernameStatus = False
            self.message = '''Invalid username. The username may only contain 
            letters (a-z), numbers (0-9), dashes (-), underscores (_), apostrophes ('), and periods (.) 
            and has to be between 5 to 20 characters'''
        else:
            self.usernameStatus = True
            
    def checkZipCode(self,zipcode):
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



    




    
    




    

