# Overview

We will be using this lab to create custom rules within AWS config. These rules will be used for the remediation of security groups according to a desired template.

This could potentially be used to ensure that a production web server security group should always have **Inbound** rules only for HTTP and HTTPS. If there is any change in the security group, the rule will be used to revert back to the original rules (i.e. Inbound only traffic permissible for HTTP and HTTPS).


## Part 1: Create a security group unrestricted SSH.

1.1. From the AWS Console, go to the VPC console.
1.2. Create a security group with SSH access which is open to anywhere.


We will be simulating Config Rule checks on the following environment:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/CustomConfigRule-Automation/images/image1-1.png )





## Part 2: Create an IAM Role For Config To Work With.

2.1. From IAM, create a Role called **MyConfigRole**. 

2.2. From the service selection menu, select **Config**.

2.3. Attach the following policies:

* AWSConfigRole
* AWSLambdaExecute
* AWSConfigRulesExecuteRole
* Add the following inline policy:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sns:Publish",
                "s3:GetBucketAcl",
                "s3:PutObject*"
            ],
            "Resource": "*",
            "Effect": "Allow"
        }
    ]
}
```

## Part 3: Set up the recorder

3.1. Go through and set up the recorder, according to the defaults.

3.2. Ensure that the role that you created in (1) is included at the bottom of the page.



## Part 4: Add the unrestricted SSH rule within AWS Config

4.1. From the management console, go to AWS Config.

4.2. From the Rules section on the left hand pane, click **Add Rule**.

4.3. Filter the rules by the keyword **ssh**.

4.4. Select the prebuilt rule **restricted-ssh**.

4.5. Select **save** to save your rule.


## Part 5: Create an SNS Topic 

5.1 Call the topic **ConfigTopic**.

5.2 Subscribe your email address and acknowledge when the confirmation mail arrives.


## Part 6: Create a Lambda Role

6.1. From the AWS management console, go to IAM.
6.2. Create a role, and choose Lambda as the service to use the role.
6.3. Create a lambda role called **MyLambdaRole** and add the following inline policy:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "config:GetComplianceDetailsByConfigRule",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:DescribeSecurityGroups",
                "ec2:RevokeSecurityGroupIngress",
                "s3:GetBucketAcl",
                "s3:PutBucketAcl",
                "sns:Publish"
            ],
            "Resource": "*",
            "Effect": "Allow"
        }
    ]
}

```




## Part 7: Create a Lambda Function for AutoRemediation

7.1 Go to the Lambda console and create a function which we will call remediate-sg.

7.2 Use the following parameters:

* Use Python 3.6 as a runtime
* Select the Lambda Role **LambdaConfigRole** which you created earlier.

When you are ready, add the following code:

```

"""
Lambda function to poll Config for noncompliant resources, and automatically
apply remediation by replacing the 0.0.0.0/0 22/tcp inbound rule with
10.10.0.0/16 22/tcp. Notifications are sent to an SNS topic.
"""

import boto3

# AWS Config settings
ACCOUNT_ID = boto3.client('sts').get_caller_identity()['Account']
CONFIG_CLIENT = boto3.client('config')
MY_RULE = "restricted-ssh"

# EC2 Settings
EC2_CLIENT = boto3.client('ec2')

# AWS SNS Settings
SNS_CLIENT = boto3.client('sns')
SNS_TOPIC = 'arn:aws:sns:us-east-1:' + ACCOUNT_ID + ':' + 'ConfigTopic'
SNS_SUBJECT = 'Compliance Update'


def lambda_handler(event, context):
    """Entry point"""

    # Get compliance details
    non_compliant_detail = CONFIG_CLIENT.get_compliance_details_by_config_rule(
        ConfigRuleName=MY_RULE, ComplianceTypes=['NON_COMPLIANT'])

    if len(non_compliant_detail['EvaluationResults']) > 0:
        print(
            'The following resource(s) are not compliant with AWS Config rule: '
            + MY_RULE)
        non_complaint_resources = ''
        for result in non_compliant_detail['EvaluationResults']:
            print(result['EvaluationResultIdentifier']
                  ['EvaluationResultQualifier']['ResourceId'])
            non_complaint_resources = non_complaint_resources + \
                result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'] + '\n'

        sns_message = 'AWS Config Compliance Update\n\n Rule: ' \
            + MY_RULE + '\n\n' \
            + 'The following resource(s) are not compliant:\n' \
            + non_complaint_resources

        SNS_CLIENT.publish(TopicArn=SNS_TOPIC,
                           Message=sns_message, Subject=SNS_SUBJECT)

        resource_type = result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']

        if resource_type == 'AWS::EC2::SecurityGroup':
            sg_id = result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
            sec_group = get_sec_group(sg_id)
            if len(sec_group) > 0:
                vpc_id = sec_group['SecurityGroups'][0]['VpcId']
                remediate_sg('10.10.0.0/16', sg_id, vpc_id)

    else:
        print('No noncompliant resources detected.')


def get_sec_group(sg_id):
    """Return the Security Group given a Security Group ID"""
    sec_group = EC2_CLIENT.describe_security_groups(Filters=[{'Name': 'group-id', 'Values': [sg_id]}])
    return sec_group


def remediate_sg(ip, sg, vpc):
    """Return EC2 SG object based on filters defined by provided VPCID/SGID"""
    sgrules = EC2_CLIENT.describe_security_groups(Filters=[
        {
            'Name': 'vpc-id',
            'Values': [vpc]
        },
        {
            'Name': 'group-id',
            'Values': [sg]
        }
    ]
    )
    r = remove_old_rule(sgrules, sg, ip)
    if r is True:
        sg_add_ingress(ip, sg)
        return True
    elif r is False:
        return False


def remove_old_rule(r, sg, ip):
    """Remove any existing rules in the SG provided the current CIDR doesn't match"""
    rules = r['SecurityGroups'][0]
    if len(rules['IpPermissions']) > 0:
        curr_ip = r['SecurityGroups'][0]['IpPermissions'][0]['IpRanges'][0]['CidrIp']
        if str(ip) == str(curr_ip):
            print('Public IP already exists')
            return False
        else:
            EC2_CLIENT.revoke_security_group_ingress(GroupId=sg, IpPermissions=rules['IpPermissions'])
            return True

    else:
        print('No security group rules for ' + sg)
        return True


def sg_add_ingress(pub_ip, sg):
    """Add ingress rule for SSH TCP/22 to the designated SG"""
    response = EC2_CLIENT.authorize_security_group_ingress(
        GroupId=sg,
        IpProtocol='tcp',
        FromPort=22,
        ToPort=22,
        CidrIp=pub_ip
    )
    return response


```

## Part 8: Auto-Remediation Via Cloudwatch Rules

8.1. Go to Cloudwatch Console.

8.2. To to Events/Rules in the left hand side tab.

8.3. Select **Create Rule**

8.3. Add the following:

* Add the rule based on schedule.
* Fix the schedule at 1 minute.
* Add the lambda function as a target.

8.4. Now click **Configure Rule**



## Part 9 : Check that it works!

9.1. Change the security group ssh settings to be open.

9.2. You should see the config rule change compliance status.

9.3. This should trigger the lambda remediation via CloudWatch Rules.

9.4. The Lambda code should lock down your open rule to the IP subrange of the on-premise DC listed above.




