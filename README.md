
Qualys WAS Burp Extension
==========================

The Qualys WAS Burp extension provides a way to easily push Burp scanner findings to the Web Application Scanning (WAS) module within the Qualys Cloud Platform. As a Qualys WAS customer, you can then view and report Burp issues alongside WAS findings for a more complete picture of your web application's security posture. 

To learn more about Qualys WAS, its integration with Burp, and the additional security and compliance solutions available in the Qualys Cloud Platform, please visit https://qualys.com/was-burp.

#### Requirements:
- Burp Suite Professional 1.7 or later
- Qualys WAS subscription, including API

#### Features:
- Straightforward setup and usage
- Supports all Qualys shared platforms as well as private cloud platforms
- Selected Burp scanner finding(s) exported to Qualys WAS via context menu
- Upstream proxy server settings in Burp are honored automatically
- Option to purge or close existing Burp issues in WAS 
- Written in Java

#### Usage:
1. Add the extension to your instance of Burp Suite Professional by installing directly from the "BApp Store" tab within Burp or by loading the jar file from the Extensions tab.
2. In the "Qualys WAS" tab, select the appropriate Qualys platform for your subscription and enter your Qualys username & password.
3. Click "Validate Credentials" to ensure successful connectivity to the Qualys platform.
4. Perform passive and/or active scans in Burp.
5. Go to: Target > Site map > Issues.
6. Right-click the desired scanner issue(s) and click "Send to Qualys WAS". 
7. Select the web application from WAS for which the issues apply. If you don't see the correct web app in the list, the web app may not have been created within WAS yet or the Qualys user account entered may not have permission to the correct web app.
8. Select the "purge" or "close" checkbox as desired.
9. Click the "Send to Qualys WAS" button.
10. View the "Logs" section on the Qualys WAS tab as needed for API success/failure messages.

#### Changelog:
** 1.0.0 30-Jul-2018
- Initial release