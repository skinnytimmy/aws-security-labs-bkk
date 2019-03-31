
# Overview

This lab will walk you through connecting to the instance and configuring security credentials so that you can interact with the AWS APIs and command line tools.  This lab will cover the following topics:
* Creating an IAM Group and adding an IAM user to the Group.
* Exploring the properties of an IAM User.
* Creating an IAM Role for EC2

# Managing AWS IAM User and Security Credentials

To generate AWS API credentials, go to the IAM dashboard in the AWS console.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image1.png "Select IAM from the console")


To create a group select "groups" then click the "Create a New Group" button.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image2.png "Select Groups")
![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image3.png "Create a New Group")

Type Power_Users into the Group Name text box and click Next Step.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image4.png "Enter Power_Users group name")

Type Power in the filtering text box and then selext PowerUserAccess. Click Next Step.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image5.png "Select PowerUserAccess From Filter")

This associate the “Power User” IAM policy to your new group and will allow group members to perform any AWS action except perform IAM management. Click Create Group:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image6.png "Select Create Group")

To create a user, select “Users” then click the “Create a New Users” button.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image7.png "Select Create New Users")

Enter ExampleUser in the first text box under Enter User Names: Unselect the check box next to Generate an access key for each user and click Create.

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image8.png "Enter ExampleUser")

Click on Close (twice)

Now click to Download Credentials:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image9.png "Download Credentials")

To add the user to the group, select ExampleUser then click on User Actions and select the Add User to Groups menu option:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image10.png "Add User To Groups")

Select the Power_Users group the click Add to Groups:

![alt text](https://github.com/skinnytimmy/aws-security-labs-bkk/blob/master/Module-1/Security-Fundamentals/images/image11.png "Add Power_Users Group To Groups")

Your new user and group have now been created, and your user is a member of your group. 


<second pic>
