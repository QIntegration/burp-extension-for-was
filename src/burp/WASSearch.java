package burp;

import java.io.StringReader;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class WASSearch
{
  private String portal_username = "";
  private String portal_password = "";
  private static String authentication_failed_code = "INVALID_CREDENTIALS";
  private  int http_Response_Code ;
  private SimpleDateFormat time_formatter = new SimpleDateFormat("yyyy-MM-dd_HH:mm:ss.SSS");
  private IBurpExtenderCallbacks callbacks;
  private String post_Url;
 
    
  public WASSearch(String post_url, String username_login, String password_login, IBurpExtenderCallbacks callbacks) {
	this.post_Url = post_url;
	portal_username = username_login;
    portal_password = password_login;
    this.callbacks = callbacks;
  } 
  
  private void disableSSLCertificateChecking()
  {
    TrustManager[] trustAllCerts = { new X509TrustManager() {
      public X509Certificate[] getAcceptedIssuers() { return null; }

      public void checkClientTrusted(X509Certificate[] arg0, String arg1)
        throws CertificateException
      {}
      


      public void checkServerTrusted(X509Certificate[] arg0, String arg1)
        throws CertificateException
      {}
    } };
    
    try
    {
      SSLContext sc = SSLContext.getInstance("TLS");
      
      sc.init(null, trustAllCerts, new SecureRandom());
      
      HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    } catch (KeyManagementException e) {
        BurpExtender.logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Exception while procesing SSL certificate checking; " + e.getMessage()+ "\n");
    	BurpExtender.logTextArea.setText(BurpExtender.logBuilder.toString());
    } catch (NoSuchAlgorithmException e) {
    	BurpExtender.logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Exception while procesing SSL certificate checking; " + e.getMessage()+ "\n");
    	BurpExtender.logTextArea.setText(BurpExtender.logBuilder.toString());
    }
  }
  
  public String getWebApplicationList()
  {
   
	String responseData = "";
    disableSSLCertificateChecking();    
  
    try {
    	
    	IExtensionHelpers helpers = callbacks.getHelpers();
    	URL url = new URL(post_Url);
    	
    	ArrayList<String> headers = new ArrayList<String>();
    	headers.add("user: " + portal_username);
    	headers.add("password: "+portal_password);
    	
    	String postJsonData = "{  \n" + 
    			"   \"ServiceRequest\":{  \n" + 
    			"      \"preferences\":{  \n" + 
    			"         \"limitResults\":1000\n" + 
    			"      } \n" + 
    			"}\n" + 
    			"}  ";
    	byte[] httpHeaders = helpers.buildHttpMessage(headers, postJsonData.getBytes());
    	   	
    	byte[] requestProps = callbacks.getHelpers().stringToBytes("POST "+url.getPath()+" HTTP/1.1\r\n"+"Content-Type: application/json"+"\r\n" +"Content-Language: en-US"+"\r\n");
    	
    	
    	byte[] hostHeaders = callbacks.getHelpers().stringToBytes("Host: "+url.getHost()+"\r\n");
    	
    	String buildRequest = new String(requestProps) + new String(hostHeaders) + new String(httpHeaders);
    	
        String protocol = url.getProtocol();
        Boolean isSSL = (protocol.equals("https"));
        
        BurpExtender.logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Making HTTP Request to : " + post_Url + "\n");
    	BurpExtender.logTextArea.setText(BurpExtender.logBuilder.toString());
        
        byte[] response = callbacks.makeHttpRequest(url.getHost(), url.getPort() == -1 ? 443 : url.getPort(), isSSL, buildRequest.getBytes());
        
        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        
        http_Response_Code = responseInfo.getStatusCode();
        int offset = responseInfo.getBodyOffset();
        byte[] responseBody = Arrays.copyOfRange(response, offset, response.length);
        responseData = new String(responseBody);
        return responseData;
    }
    catch (Exception e) {
      http_Response_Code = -1; // it means an error is encountered
      BurpExtender.logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Exception while fetching webapps; Please check credentials: " + e.getMessage()+ "\n" + "###### Response Data ##### \n" +responseData+"\n");
  	  BurpExtender.logTextArea.setText(BurpExtender.logBuilder.toString());
    } 
    return responseData;
  }
  
  public String getResponseCode(String response)
  {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance(); 
    String response_message_code = "";
    try {
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document doc = builder.parse(new InputSource(new StringReader(response)));
      NodeList listofErrorResponse = doc.getElementsByTagName("responseCode");
      Node responseMessage = listofErrorResponse.item(0);
      if (responseMessage.getNodeType() == 1) {
        response_message_code = responseMessage.getFirstChild().getNodeValue();
      }
    }
    catch (Exception e)
    {
    	BurpExtender.logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Exception ; " + e.getMessage()+ "\n");
    	BurpExtender.logTextArea.setText(BurpExtender.logBuilder.toString());
    	return authentication_failed_code;
    }
    
    return response_message_code;
  }
  
  public boolean checkAuthenticationStatus(String response)
  {
	if( http_Response_Code!=200){
		return false;
	}
	else{
       String authentication_response = getResponseCode(response);
       if (authentication_response.equals(authentication_failed_code))
          return false;
       return true;
	}
  }
   

  public ArrayList<WebAppItem> parseWebApplications(String response)
  {
    ArrayList<WebAppItem> webapplists = new ArrayList<WebAppItem>();
    
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    try
    {
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document doc = builder.parse(new InputSource(new StringReader(response)));
      NodeList listofWebApplications = doc.getElementsByTagName("WebApp");
      NodeList listofErrorResposne = doc.getElementsByTagName("responseCode");
      if ((listofWebApplications != null) && (listofWebApplications.getLength() > 0))
      {
        int nodeCount = listofWebApplications.getLength();
        for (int i = 0; i < nodeCount; i++) {
          Node webappNode = listofWebApplications.item(i);
          if (webappNode.getNodeType() == 1) {
            Element webAppElement = (Element)webappNode;
            Node webapp_ID_Node = webAppElement.getElementsByTagName("id").item(0);
            String webApp_id = webapp_ID_Node.getFirstChild().getNodeValue();
           
            Node webapp_Name_Node = webAppElement.getElementsByTagName("name").item(0);
            String webApp_name = webapp_Name_Node.getFirstChild().getNodeValue();
           
            Node webapp_URL_Node = webAppElement.getElementsByTagName("url").item(0);
            String webApp_URL = webapp_URL_Node.getFirstChild().getNodeValue();
            
            WebAppItem webAppItem = new WebAppItem(webApp_id, webApp_name, webApp_URL);
            webapplists.add(webAppItem);
          }
        }
      }
      else
      {
        Node authErrorMessage = listofErrorResposne.item(0);
        if (authErrorMessage.getNodeType() == 1) {
          BurpExtender.logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Error msg = " + authErrorMessage.getFirstChild().getNodeValue()+ "\n");
      	  BurpExtender.logTextArea.setText(BurpExtender.logBuilder.toString());
        }
      }
    }
    catch (Exception e) {
    	BurpExtender.logBuilder.append(time_formatter.format(System.currentTimeMillis()) + " : Error fetching and parsing the web apps list for given platform; exception = " + e.getMessage()+ "\n");
    	BurpExtender.logTextArea.setText(BurpExtender.logBuilder.toString());
    }
    Collections.sort(webapplists);
    return webapplists;
  }
}
