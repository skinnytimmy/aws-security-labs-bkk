
# Overview

This lab will show you some of the basics concerning security automation. There are a number of ways to automate security best practice, which will be demonstrated with the following examples:

* Using **Cloudwatch Rules** to automate the enabling of **Cloudtrail**
* Using **AWS Config** to automate the templating of security group rules within an enterprise organization.


Please note that these labs are designed to show the capabilities of automation as a security best practice. All code within this example should be used for demonstration purposes only.


# Cloudtrail Automation via Cloudwatch Rules


## Check if CloudTrail has a Configured Trail

**Note:** In order for this lab to complete successfully, you should ensure that you continue to use the region in which you have previously created and configured trails. 

To check if you have created a previous trail:

* Sign in to the console and open **AWS CloudTrail**
* Select **Trail** from the left pane.
* Note the name of the trail that you have configured.
* Note the **region** in the top right hand of the **Trail Configuration** page.
* Continue to use the same region for the rest of the lab.


## Create a CloudTrail Trail [if You Have Not Prevuously]

If you have not created a trail previously, please create one as follows:


* Sign in to the console and open **AWS CloudTrail**
* Click on **Trails** in the left hand pane.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-1.png )

* Click on **Create Trail** to enter the trail creation page:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-2.png )

* Give your trail a name and ensure that all management events are recorded across all regions:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-3.png )

For storage location, set the following:

1. Create a new S3 bucket with a unique name. 
2. Encrypt the log files with SSE-KMS.
3. Create a new KMS key.
4. Enter a unique name for your KMS key.
5. Enable log file validation.
6. Turn off SNS notification.

When this is completed, you can select create.



## Create an SNS Topic For CloudTrail Monitoring Alert.

From the management console, open the SNS console.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-5.png )


From the SNS console, create a topic called **CLoudTrailNotify** and click **Next Step**


![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-6.png )

For brevity in the lab, click **Create topic**

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-7.png )

Note down the ARN details for later in the lab.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-8.png )


Now click on **Create Subscription** and select **Email** as the protocol. Add your email address as an endpoint and select **Create Subscription**


![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-9.png )


You will now receive a subscription email which you will need to acknowledge. When the confirmation is completed, the status will change within the console.


![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-10.png )


## Create an IAM Policy for Lambda to turn on CloudTrail

* Sign into IAM Console
* Select **Policies** from the left hand pane.
* Select **Create policy**
* Select JSON from the tabs, and enter the following lambda code:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "LambdaCloudtraiMonitor",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:StartLogging"
            ],
            "Resource": [
                "arn:aws:cloudtrail:*:<AWS-ACCOUNT-ID>:trail/*"
            ]
        },
        {
            "Sid": "CloudWacthLogspermissions",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:*:*:*"
            ]
        },
        {
            "Sid": "SNSPublishpermissions",
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": [
                "arn:aws:sns:*:*:*"
            ]
        }
    ]
}

```

**IMPORTANT** !!!Make sure that you replace the account number in the resource section above!!!


Finally select **Review Policy**

* Name the policy **cloudtrail-remediation-lambda**
* Give it a meaningful description.
* Select **Create Policy**

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-11.png )


## Create an IAM Role for Your Lambda Function

* Select Lambda from the Management Console.
* From the dashboard, select **Create a function**

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-12.png )

* Select **Author from scratch**.
* Under **Basic Information** give the function the name **CloudTrailAutoResponder**
* Select **Python 2.7** as the runtime.
* In the execution role, enter the role **CloudTrailRemediationLambdaRole** which you created previously.
* Click on **Create Function**


![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-13.png )

* Paste the following code into the function window:


```

# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
# Description: Lambda function that sends notification on AWS CloudTrail changes and when a trail gets disabled it re-enables it back.
#
# Cloudtraillambdamonitor.py
#
# Author: Sudhanshu Malhotra, sudmal@amazon.com
# Date: 2017-06-08
#
#

import json
import time
import boto3
import logging
import os
import botocore.session
from botocore.exceptions import ClientError
session = botocore.session.get_session()

logging.basicConfig(level=logging.DEBUG)
logger=logging.getLogger(__name__)

# Defines Lambda function for automatically enabling AWS CloudTrail logs when it gets disabled
# and publish notification to SNS Topic on any changes to the AWS CloudTrail.

def lambda_handler(event, context):
    logger.setLevel(logging.DEBUG)
    eventname = event['detail']['eventName']
    snsARN = os.environ['SNSARN']          #Getting the SNS Topic ARN passed in by the environment variables.
    logger.debug("Event is-- %s" %event)
    logger.debug("Event Name is--- %s" %eventname)
    logger.debug("SNSARN is-- %s" %snsARN)
    snsclient = boto3.client('sns')
    
# If the CloudTrail Logging is disabled we will send a notification for that
# and revert it back to enabled state. Note:- This automatic starting of logging will generate another SNS notification.
    
    if (eventname == 'StopLogging'):
        cloudtrailArn= event['detail']['requestParameters']['name']
        logger.info("AWS CloudTrail logging disabled for AWS Cloudtrail with ARN-- %s. Enabling the AWS Cloudtrail back again....." %cloudtrailArn)
        
        #Sending the notification that the AWS CloudTrail has been disabled.
        snspublish = snsclient.publish(
                         TargetArn = snsARN,
                         Subject=("CloudTrail event- \"%s\" received. Will automatically enable logging." %eventname),
                         Message=json.dumps({'default': json.dumps(event)}),
                         MessageStructure='json')
      
       #Enabling the AWS CloudTrail logging
        
        try:
            client = boto3.client('cloudtrail')
            enablelogging = client.start_logging(Name=cloudtrailArn)
            logger.debug("Response on enable CloudTrail logging- %s" %enablelogging)

        except ClientError as e:
           logger.error("An error occured: %s" %e)

# Anything other than "StopLogging" event such as update, add/remove tags, create new trail etc.
# just a notification is sent to the Amazon SNS topic subscribers.
    
    else:
        logger.info("The CloudTrail event was %s, sending email to the SNS topic subscribed" %eventname)
        
        try:
            
            #Sending the notification that a change has been made in AWS CloudTrail other than disabling it.
            snspublish = snsclient.publish(
                         TargetArn= snsARN,
                         Subject=("CloudTrail event- \"%s\" received" %eventname),
                         Message=json.dumps({'default': json.dumps(event)}),
                         MessageStructure='json')
            logger.debug("SNS Publish Response- %s" %snspublish)
        
        except ClientError as e:
           logger.error("An error occured: %s" %e)



 ```

 Configure the environment variables as follows: 

 * Key: **SNSARN**
 * Value: **<Enter the SNSARN from the topic that you created earlier>**

 Save the function by selecting **SAVE** at the top of the page.


![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-5/Security-Automation/images/image5-1-14.png )


## Create and Configure a Cloudwatch Event to Detect the Event and Trigger Remediation

* Open CloudWatch in the Mangement Console.
* Under the **Events** section in the left hand pane, select **Rules**.
* Select **Create Rule**

Enter the following detail:

* Build a pattern to match - Event By Service
* Service Name: **CloudTrail**
* Event Type: **AWS API call via CloudTrail**
* Specific Operations: Enter the following as separate line items - **StopLogging, StartLogging, UpdateTrail, DeleteTrail, CreateTrail, RemoveTags, AddTags, PutEventSelectors.**

The code in the preview pane should look like the following output:

```
{
  "source": [
    "aws.cloudtrail"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "cloudtrail.amazonaws.com"
    ],
    "eventName": [
      "StopLogging",
      "StartLogging",
      "UpdateTrail",
      "DeleteTrail",
      "CreateTrail",
      "RemoveTags",
      "AddTags,",
      "PutEventSelectors"
    ]
  }
}
```

Now select **Add Target** to enter the remediation details:

* Provide your function name **CloudTrailAutoResponder** 
* Click **Configure Details**

In the **Rule Definition** enter the following:

* Enter **CloudTrailMonitor** for the name.

Now click **Create Rule**


##Now verify that it all works!

* In the management console, select CloudTrail
* Select **Trail** from the left pane.
* Select the trail that you configured previously.
* Turn it off in the top right hand corner of the console.
* Wait and have a cup of tea. If you have configured correctly, CloudTrail should utilize the automation and re-enable itself.









