# igarcia 2021-10
# Version 1.2.0
# Automation to Secure Bastion Host (Administration Instance Linux/Windows)
# Cleaner function to remove expired rules in NACL and updates DynamoDB table

import json
import boto3
import os
import datetime
from boto3.dynamodb.conditions import Key

session = boto3.session.Session()
dynamodb = session.resource('dynamodb')
table = dynamodb.Table(os.environ['DDBTABLE'])
ec2 = session.resource('ec2')
nacl = ec2.NetworkAcl(os.environ['NACLID'])
days_block = int(os.environ['BLOCKDAYS'])

def lambda_handler(event, context):

    free_rules = []
    
    # Finds date to clean
    curr_date = datetime.datetime.now()
    delta = datetime.timedelta(days=days_block)
    clean_date = (curr_date - delta).strftime("%Y-%m-%d")

    # Gets Rules by date to clean
    rules = table.scan(
        ProjectionExpression="pk, #rule",
        Select="SPECIFIC_ATTRIBUTES",
        FilterExpression=Key("date").lt(clean_date),
        ExpressionAttributeNames={"#rule": "rule"}
    )
    for rule in rules['Items']:
        rule_n = int(rule['rule'])
        try:
            response = nacl.delete_entry(Egress=False,RuleNumber=rule_n)
            response = table.delete_item(Key={"pk":rule['pk']})
            free_rules.append(rule_n)
        except Exception as e:
            print("Unable to remove Rule.")
            print(e)
    
    while 'LastEvaluatedKey' in rules:
        # Gets more Rules by date to clean
        rules = table.scan(
            ProjectionExpression="pk, #rule",
            Select="SPECIFIC_ATTRIBUTES",
            FilterExpression=Key("date").lt(clean_date),
            ExpressionAttributeNames={"#rule": "rule"},
            ExclusiveStartKey=rules['LastEvaluatedKey']
        )
        for rule in rules['Items']:
            rule_n = int(rule['rule'])
            try:
                response = nacl.delete_entry(Egress=False,RuleNumber=rule_n)
                response = table.delete_item(Key={"pk":rule['pk']})
                free_rules.append(rule_n)
            except Exception as e:
                print("Unable to remove Rule.")
                print(e)

    print("Removed {} rules.".format(len(free_rules)))
    
    # Gets available Rule numbers
    nextrule = table.get_item(Key={"pk":"nextrule"})
    
    # True if there are no rules yet
    if not nextrule.get('Item'):
        new_nextrule = set(free_rules)
    else:
        nextrule_list = list(nextrule['Item']['rule'])
        new_nextrule = set(free_rules+nextrule_list)
        response = table.put_item(Item={"pk":"nextrule","rule":new_nextrule,"lastdate":curr_date.strftime("%Y-%m-%d")})
    
    return None
