import random

def main():
    firewallRules = {
        "192.168.1.1": "block",
        "192.168.1.4": "block",
        "192.168.1.9": "block",
        "192.168.1.13": "block",
        "192.168.1.16": "block",
        "192.168.1.19": "block"
    }
    #indicates 6 arbitrary IP addresses that we want to block
    #for the purposes of simulation, 6 addresses that I want to
    #not allow onto the internal network 
    for _ in range(12): #for loop that runs 12 times to simulate network traffic
        ipAddress = generateRandomIp() #generates random IP address
        action = checkFirewallRules(ipAddress, firewallRules)
        randomNum = random.randint(0, 9999) #unique identifier for each request
        print(f"IP: {ipAddress}, Action: {action}, Random: {randomNum}") 

def generateRandomIp():
    return f"192.168.1.{random.randint(0, 20)}"
    #returns a random IP address that represents the source IP

def checkFirewallRules(ip, rules):
    for ruleIP, action in rules.items(): #unpacks dictionary by using items function
    #for each IP on our block list, it'll compare randomly generated IP to see if they match
        if ip == ruleIP:
            return action
    return "allow"
#if it finds a match, it'll return the action associated with that IP address, which is 'block'
#if not a match, it will allow the IP address to pass onto our internal network

if __name__ == "__main__":
    main()
#ensures that when script is executed, main function is called