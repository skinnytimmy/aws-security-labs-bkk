
# Overview

This lab will walk you through connecting to the instance and configuring security credentials so that you can interact with the AWS APIs and command line tools.  This lab will cover the following topics:
* Creating an IAM Group and adding an IAM user to the Group.
* Exploring the properties of an IAM User.
* Creating an IAM Role for EC2

# Managing AWS IAM User and Security Credentials

To generate AWS API credentials, go to the IAM dashboard in the AWS console.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image1.png "Select IAM from the console")


To create a group select **groups** then click the **Create a New Group** button.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image2.png "Select Groups")
![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image3.png "Create a New Group")

Type **Power_Users** into the Group Name text box and click Next Step.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image4.png "Enter Power_Users group name")

Type **Power** in the filtering text box and then selext **PowerUserAccess**. Click **Next Step**:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image5.png "Select PowerUserAccess From Filter")

This associate the **Power User** IAM policy to your new group and will allow group members to perform any AWS action except perform IAM management. Click **Create Group**:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image6.png "Select Create Group")

To create a user, select **Users** then click the **Create a New Users** button.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image7.png "Select Create New Users")

Enter **ExampleUser** in the first text box under "Enter User Names:" Unselect the check box next to "Generate an access key" for each user and click **Create**.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image8.png "Enter ExampleUser")

Click on Close (twice)

Now click to Download Credentials:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image9.png "Download Credentials")

To add the user to the group, select **ExampleUser** then click on **User Actions** and select the "Add User to Groups" menu option:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image10.png "Add User To Groups")

Select the **Power_Users** group the click "Add to Groups":

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image11.png "Add Power_Users Group To Groups")

Your new user and group have now been created, and your user is now a member of your group. 



# Managing IAM User Permissions and Credentials

Now that you have created your first IAM user and group, lets take a look at the IAM user properties.  Click on the **Users** option in the left-hand menu, then select the ExampleUser account that you just created: 

Notice the user is a member of the Power_Users group that you added them to.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image2-1.png "Confirm group membership")

Now select the **Permissions** tab to see the individual User and Group Policies that will be applied to this account. Note that this user only has the PowerUserAccess group policy applied to the account:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image2-2.png "View user permissions")

Now select **Security Credentials**. This is where you can assign or change a User’s Console Password and Multi-Factor Authentication device:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image2-3.png "View security credentials")

From here you can also Create, Rotate, or Revoke a user’s API Access Keys (for using the AWS Command Line tools or other direct access to the AWS APIs through custom or 3rd party applications):

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image2-4.png "View API Access Key Details")


# IAM Roles for EC2

Applications or Command Line Tools running on Amazon Elastic Compute Cloud (Amazon EC2) instances that make requests to Amazon Web Services (AWS) must sign all AWS API requests with AWS access keys. AWS Identity and Access Management (IAM) Roles for EC2 instances, is a feature that makes it easier for your applications and command line tools to securely access AWS service APIs from EC2 instances. An IAM role with a set of permissions can be created and attached to an EC2 instance on launch.  AWS access keys with the specified permissions will then be automatically made available on EC2 instances that have been launched with an IAM role. IAM roles for EC2 instances manages the muck of securely distributing and rotating your AWS access keys out to your EC2 instances so that you don’t have to.
Using IAM roles for instances, you can securely distribute AWS access keys to instances and define permissions that applications on those instances use when accessing other services in AWS. Here are some things you should know about using IAM roles for instances:


* AWS access keys for signing requests to other services in AWS are automatically made available on running instances.
* AWS access keys on an instance are rotated automatically multiple times a day. New access keys will be made available at least five minutes prior to the expiration of the old access keys.
* You can assign granular service permissions for applications running on an instance that make requests to other services in AWS.
* You can include an IAM role when you launch On-Demand, Spot, or Reserved Instances.
* IAM roles can be used with all Windows and Linux AMIs. 

To create an IAM Role for EC2, click on the **Roles** link on the left-hand menu and click **Create New Role**:


