# igarcia 2020-04
# Version 1.0
# Automation to Secure Bastion Host (Administration Instance Linux/Windows)
# Gets updates from GuardDuty (must be already configured) and blocks the CIDR /24 of attackers
# Main function to create entries in the NACL specified and updates de DynamoDB table

import json
import boto3
import os
from boto3.dynamodb.conditions import Key

session = boto3.session.Session()
dynamodb = session.resource('dynamodb')
table = dynamodb.Table(os.environ['DDBTABLE'])
ec2 = session.resource('ec2')
nacl = ec2.NetworkAcl(os.environ['NACLID'])

SPACE = 5
BASE_RULE = int(os.environ['BASERULE'])
MAX_RULE = int(os.environ['MAXRULE'])*SPACE
NACL_ID = os.environ['NACLID']

def lambda_handler(event, context):
    
    # Gets DATA from event
    e_date = event['detail']['service']['eventLastSeen']
    e_ip = event['detail']['service']['action']['networkConnectionAction']['remoteIpDetails']['ipAddressV4']
    e_country = event['detail']['service']['action']['networkConnectionAction']['remoteIpDetails']['country']['countryName']
    e_type = event['detail']['type'].split('/')[1]
    cidr = '.'.join(e_ip.split('.')[0:3])+'.0/24'
    port = 0
    cidr_del = ""
    to_remove = False
    
    if e_type == 'RDPBruteForce': port = 3389
    if e_type == 'SSHBruteForce': port = 22

    # Gets Next Rule Number(s)
    nextrule = table.get_item(Key={"pk":"nextrule"}) 

    # TRUE if is not the first run
    if nextrule.get('Item'):
        nextrule_list = list(nextrule['Item']['rule'])
        nextrule_list.sort()    # Rules numbers sorted from small to big
        nextrule_n = int(nextrule_list.pop(0))
        new_nextrule = set(nextrule_list)
        
        if not new_nextrule:
            new_nextrule = {nextrule_n+SPACE}
            
    else:
        nextrule_n = BASE_RULE # Regla inicial
        new_nextrule = {nextrule_n+SPACE} 
    
    # Checks the limit of Rules to Create
    if nextrule_n >= BASE_RULE + MAX_RULE:
        new_nextrule = {BASE_RULE + MAX_RULE}

        # Will replace the oldest rule
        rules = table.scan(
            ProjectionExpression="pk, #rule, #date",
            Select="SPECIFIC_ATTRIBUTES",
            FilterExpression=Key("pk").begins_with("cidr#"),
            ExpressionAttributeNames={"#rule": "rule","#date": "date"}
        )
        dates = []

        for rule in rules['Items']:
            dates.append(rule['date'])

        dates.sort()    # Dates sorted from oldest to newest
        rule = None

        for rule in rules['Items']:
            if rule['date'] == dates[0]:  # Found oldest rule
                nextrule_n = int(rule['rule'])
                cidr_del = rule['pk']
                to_remove = True
                break
        print("MAX_RULE reached. Oldest rule replaced.")
    
    # Updates Rules in DynamoDB
    try:
        response = table.put_item(
            Item = {
                "pk":"cidr#"+cidr,
                "country":e_country,
                "rule":nextrule_n,
                "date":e_date,
                "type":e_type
            },
            ConditionExpression = "attribute_not_exists(pk)"
        )
        if to_remove:
            response = nacl.delete_entry(Egress=False,RuleNumber=nextrule_n)
            response = table.delete_item(Key={"pk":cidr_del})
    except Exception as e:
        # If Rule already Exist, Updates new date
        if e.response['Error']['Code'] == "ConditionalCheckFailedException":
            rule_db = table.get_item(Key={"pk":"cidr#"+cidr})
            response = table.put_item(
                Item = {
                    "pk":rule_db['Item']['pk'],
                    "country":rule_db['Item']['country'],
                    "rule":int(rule_db['Item']['rule']),
                    "date":e_date,
                    "type":rule_db['Item']['type']
                }
            )
            print("Rule updated: Rule {} BLOCK CIDR {} PORT {}".format(int(rule_db['Item']['rule']),cidr,port))
    else:
        # Updates Next Rule number in DynamoDB
        response = table.put_item(Item={"pk":"nextrule","rule":new_nextrule,"lastdate":e_date})
        
        # Modifies NACL
        response = nacl.create_entry(
            CidrBlock=cidr,
            Egress=False,
            PortRange={'From':port, 'To':port},
            Protocol="6", #TCP
            RuleAction='deny',
            RuleNumber=nextrule_n
        )
        print("Rule added: Rule {} BLOCK CIDR {} PORT {}".format(nextrule_n,cidr,port))
    
        return None
