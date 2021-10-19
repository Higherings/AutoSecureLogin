# AutoSecureLogin IS NOW AutoSecureNetwork
Easy to configure automation to automatically secure the Subnets where run your Public Instances by NACL DENY entries feeded by GuardDuty findings.
It uses CloudFormation, Lambda (Python - ARM), CloudWatch Events, DynamoDB and Amazon GuardDuty (should be already working on the account).

When GuardDuty alerts of RDPBruteForce, SSHBruteForce, PortProbeUnprotectedPort attacks it will automatically block ALL traffic by a DENY rule in the NACL with the offending IPs (whole CIDR /24).

The rules are added automatically in spaces of 5, so you can add custom rules to allow specific IPs in the CIDR that is blocked.

It also has a configurable duration of the block (in days) and a Max number of IPs to collect.

If it's not working on your Region create an Issue and I will fix it.

> Version 2.0.0

### Files:
- autoSecureLogin-template.yml, CloudFormation template to Run in your account, it is already in a public S3 bucket

- autosecurelogin.py, Lambda code that actually do the job of creating the entries in the NACL, source code only for reviewing

- autosecurelogin.zip, Zip file used by the template to deploy de Lambda, it is already in a public S3 Bucket

- autosecurelogin-cleaner.py, Lambda code that cleans up the expired entries , source code only for reviewing

- autosecurelogin-cleaner.zip, Zip file used by the template to deploy de Lambda, it is already in a public S3 Bucket

## How To Deploy
Use AWS CloudFormation to deploy the following template:

https://higher-artifacts.s3.amazonaws.com/solutions/autoSecureLogin-template.yml

### Parameters:
- *Env Tag*, use to identified the components of the template

- *Days blocked*, sets the number of days to keep the DENY rule in place

- *MAX number of IPs blocked*, sets the number of IPs to collect (will be the number of DENY rules to create)

- *NACL ID*, specify the ID of the Network Access Control List to use

`If you edit the template remember to use LF end of lines.`

`VPC NACL has a limit of 20 rules, thus the MAX number of IPs blocked is set at 15 as default.`

#### Notes:

- Function blocks ALL traffic  from offending IPs

- Function uses the CIDR /24 of the offending IPs 

- Function is triggered with SSH attacks, RDP attacks and Port Probe attacks

- If the MAX rules is reached, the older one will be replace even if is not expired

## To-Do
- A better error management
