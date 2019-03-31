# Overview

We will be using this lab to create custom rules within AWS config. These rules will be used for the remediation of security groups according to a desired template.

This could potentially be used to ensure that a production web server security group should always have **Inbound** rules only for HTTP and HTTPS. If there is any change in the security group, the rule will be used to revert back to the original rules (i.e. Inbound only traffic permissible for HTTP and HTTPS).


## Part 1: Create a security group with inbound rules only for HTTP and HTTPS.

* Open the management console, and go to the VPC console.
* In the navigation pane, choose **Security Groups**.
* Select **Create Security Group**
* Provide the name as **WebServerSGDemo** and give an appropriate description.
* Now select the security group and update the **Inbound** rules. The details pane displays the details for the security group, plus tabs for working with its inboud rules and outbound rules.
* On the **Inbound Rules** tab, choose **Edit**. Select an option for a rule for inbound traffic and create rules with the below details:

From **Type** choose **HTTP** and specify a value for **Source** as **0.0.0.0/0**
From **Type** choose **HTTPS** and specify a value for **Source** as **0.0.0.0/0**

**Note:**  !!Make note of the security group ID as you will need it later on!!




##Part 2: Create an IAM Policy for a Lambda Function to Remediate the Security Group

2.1. From the AWS console, select IAM.

2.2. Select **Policy** from the left panel.

2.3. Select **JSON** from the tab and paste the following policy into the window:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "config:PutEvaluations",
                "ec2:DescribeSecurityGroups",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "*"
        }
    ]
}

```

2.4. Click **Review Policy**

2.5. Provide the policy name as **WebSGMonitorLambdaPolicy**

2.6. Click **Create Policy**





## Part 3 - Create an IAM Role for your Lambda Function





3.1. From the IAM console, select **Role** from the left hand panel.

3.2. Select **Create Role**

3.3. Select **Lambda** from the list of services that will use this rile and then select **Next : Permission**

3.4. In the search box, enter the policy name which we created previously - **WebSGMonitorLambdaPolicy** and then select **Next: Review**

3.5. Name your role **WebSGRemediationLambdaRole** and provide a description.

3.5. Select **Create Role**





## Part 4 - Creating the Lambda Function

4.1. In the AWS management console, select **Lambda** to go to the Lambda console.

4.2. From the dashboard, select **Create Function**.

4.3. On the create function page, choose **Author From Scratch**

4.4. Provide a name for the function. For this exercise, we will call the lambda function **WebSGAutoResponder**

4.5. In the runtime, select **Python 2.7**

4.6. Under role, select **Choose An Existing Role**, and select the role that we created previously - **WebSGRemediationLambdaRole** and then select **Create function**

4.7. On the function **configuration** page, scroll down to **Basic Settings** and change **Timeout** value to 15 seconds.

4.8. Scroll up to the **designer** section and select the name of your lambda function and delete the default code and paste the following code in its place:

```

#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# This code is only intended for instructional purposes and should not be used for any other use.

import boto3
import botocore
import json

 
APPLICABLE_RESOURCES = ["AWS::EC2::SecurityGroup"]

# Specify the required ingress permissions using the same key layout as that provided in the
# describe_security_group API response and authorize_security_group_ingress/egress API calls.

REQUIRED_PERMISSIONS = [
{
    "IpProtocol" : "tcp",
    "FromPort" : 80,
    "ToPort" : 80,
    "UserIdGroupPairs" : [],
    "IpRanges" : [{"CidrIp" : "0.0.0.0/0"}],
    "PrefixListIds" : [],
    "Ipv6Ranges": []
},
{
    "IpProtocol" : "tcp",
    "FromPort" : 443,
    "ToPort" : 443,
    "UserIdGroupPairs" : [],
    "IpRanges" : [{"CidrIp" : "0.0.0.0/0"}],
    "PrefixListIds" : [],
    "Ipv6Ranges": []
}]

# normalize_parameters
#
# Normalize all rule parameters so we can handle them consistently.
# All keys are stored in lower case.  Only boolean and numeric keys are stored.

def normalize_parameters(rule_parameters):
    for key, value in rule_parameters.iteritems():
        normalized_key=key.lower()
        normalized_value=value.lower()

        if normalized_value == "true":
            rule_parameters[normalized_key] = True
        elif normalized_value == "false":
            rule_parameters[normalized_key] = False
        elif normalized_value.isdigit():
            rule_parameters[normalized_key] = int(normalized_value)
        else:
            rule_parameters[normalized_key] = True
    return rule_parameters

# evaluate_compliance
#
# This is the main compliance evaluation function.
#
# Arguments:
#
# configuration_item - the configuration item obtained from the AWS Config event
# debug_enabled - debug flag
#
# return values:
#
# compliance_type -
#
#     NOT_APPLICABLE - (1) something other than a security group is being evaluated
#                      (2) the configuration item is being deleted
#     NON_COMPLIANT  - the rules do not match the required rules and we couldn't
#                      fix them
#     COMPLIANT      - the rules match the required rules or we were able to fix
#                      them
#
# annotation         - the annotation message for AWS Config

def evaluate_compliance(configuration_item, debug_enabled):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type" : "NOT_APPLICABLE",
            "annotation" : "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
        }

    if configuration_item["configurationItemStatus"] == "ResourceDeleted":
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The configurationItem was deleted and therefore cannot be validated."
        }

    group_id = configuration_item["configuration"]["groupId"]
    client = boto3.client("ec2");

    # Call describe_security_groups because the IpPermissions that are returned
    # are in a format that can be used as the basis for input to
    # authorize_security_group_ingress and revoke_security_group_ingress.

    try:
        response = client.describe_security_groups(GroupIds=[group_id])
    except botocore.exceptions.ClientError as e:
        return {
            "compliance_type" : "NON_COMPLIANT",
            "annotation" : "describe_security_groups failure on group " + group_id
        }
        
    if debug_enabled:
        print("security group definition: ", json.dumps(response, indent=2))

    ip_permissions = response["SecurityGroups"][0]["IpPermissions"]
    authorize_permissions = [item for item in REQUIRED_PERMISSIONS if item not in ip_permissions]
    revoke_permissions = [item for item in ip_permissions if item not in REQUIRED_PERMISSIONS]

    if authorize_permissions or revoke_permissions:
        annotation_message = "Permissions were modified."
    else:
        annotation_message = "Permissions are correct."

    if authorize_permissions:
        if debug_enabled:
            print("authorizing for ", group_id, ", ip_permissions ", json.dumps(authorize_permissions, indent=2))

        try:
            client.authorize_security_group_ingress(GroupId=group_id, IpPermissions=authorize_permissions)
            annotation_message += " " + str(len(authorize_permissions)) +" new authorization(s)."
        except botocore.exceptions.ClientError as e:
            return {
                "compliance_type" : "NON_COMPLIANT",
                "annotation" : "authorize_security_group_ingress failure on group " + group_id
            }

    if revoke_permissions:
        if debug_enabled:
            print("revoking for ", group_id, ", ip_permissions ", json.dumps(revoke_permissions, indent=2))

        try:
            client.revoke_security_group_ingress(GroupId=group_id, IpPermissions=revoke_permissions)
            annotation_message += " " + str(len(revoke_permissions)) +" new revocation(s)."
        except botocore.exceptions.ClientError as e:
            return {
                "compliance_type" : "NON_COMPLIANT",
                "annotation" : "revoke_security_group_ingress failure on group " + group_id
            }

    return {
        "compliance_type": "COMPLIANT",
        "annotation": annotation_message
    }

# lambda_handler
#
# This is the main handle for the Lambda function.  AWS Lambda passes the function an event and a context.
# If "debug" is specified as a rule parameter, then debugging is enabled.

def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event["configurationItem"]
    rule_parameters = normalize_parameters(json.loads(event["ruleParameters"]))

    debug_enabled = False

    if "debug" in rule_parameters:
        debug_enabled = rule_parameters["debug"]

    if debug_enabled:
        print("Received event: " + json.dumps(event, indent=2))

    evaluation = evaluate_compliance(configuration_item, debug_enabled)

    config = boto3.client('config')

    response = config.put_evaluations(
       Evaluations=[
           {
               'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
               'ComplianceType': evaluation["compliance_type"],
               "Annotation": evaluation["annotation"],
               'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
           },
       ],
       ResultToken=event['resultToken'])
       
 ```

## Part 5: Create a Custom Config Rule to Monitor Configuration Changes in Security Groups and Invoke Lambda.

5.1. From the management console, open the AWS Config Console.

5.2. In the management console, ensure that you are running AWS config in the **SAME REGION** in which you created the AWS Lambda function for your custom rule.

5.3. On the **Rules** page, choose **Add Rule**

5.4. On the **Add Rule** page, choose **Add Custom Rule**

5.5. On the **Configure Rule** page, complete the following steps:

* For **Name** enter **WebSGMonitorRule**
* For **AWS Lambda function ARN**, specify the ARN of lambda function **WebSGAutoResponder** we created earlier
* For **Trigger type**, choose **Configuration changes**. 
* For **Scope of changes**, choose **Resources**. 
* For **Resources**, choose **SecuityGroup**.
* For Resource Identifier provide **group ID** of security group **WebServerSGDemo** we created earlier (e.g. sg-549654u6549ddd).
* Select **Save**


