# AutoSecureLogin
Easy to configure automation to automatically secure the Subnet where runs your Bastion Host by NACL DENY entries feeded by GuardDuty findings.
It uses CloudFormation, Lambda, CloudWatch Events, DynamoDB and Amazon GuardDuty (should be already working on the account).

When GuardDuty alerts of RDPBruteForce or SSHBruteForce attacks it will automatically block by a DENY rule in the NACL the offending IPs (whole CIDR /24).

The rules are added automatically in spaces of 5, so you can add custom rules to allow specific IPs in the CIDR is blocked.

It also has a configurable duration of the block (in days) and a Max number of IPs to collect. REMEMBER to put your ALLOW rules in a higher number than MAX (number of IPs) x 5. Example: if MAX (number of IPs) is 50, AutoSecureLogin will use the rule numbers from 10 to 250, and you should start putting your ALLOW rules above that number.

> Version 0.1

### Files:
- autoSecureLogin-template.yml, CloudFormation template to Run in your account, it is already in a public S3 bucket

- autosecurelogin.py, Lambda code that actually do the job of creating the entries in the NACL, source code only for reviewing

- autosecurelogin.zip, Zip file used by the template to deploy de Lambda, it is already in a public S3 Bucket

- autosecurelogin-cleaner.py, Lambda code that cleans up the expired entries , source code only for reviewing

- autosecurelogin-cleaner.zip, Zip file used by the template to deploy de Lambda, it is already in a public S3 Bucket

## How To Deploy
Use AWS CloudFormation to deploy the following template:

https://higher-artifacts.s3.amazonaws.com/autoSecureLogin-template.yml

### Parameters:
- *Env Tag*, use to identified the components of the template

- *Days blocked*, sets the number of days to keep the DENY rule in place

- *MAX number of IPs blocked*, sets the number of IPs to collect (will be the number of DENY rules to create)

- *NACL ID*, specify the ID of the Network Access Control List to use

`If you edit the template remember to use LF end of lines.`

#### Notes:

- Function uses the CIDR /24 of the offending IPs 

- Function is triggered with both SSH attacks and RDP attacks

## To-Do
- Updates more than one NACL with the rules

- Creates two rules each time for SSH and RDP, right now only creates for the type of attack in the finding

- A better error management
