/**
 * 
 */
package com.rabit.credentialhelper;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;


public class AWSCodeCommitHttpCredentials {
	
	final private static char[] hexArray = "0123456789abcdef".toCharArray();
	private final String orgName_proName;
	private final String httpUrl;
	private final String userName;
    private final String password;
    
    
    
    public static void main(String[] args) {
//    	new AWSCodeCommitHttpCredentials(args[0], args[1], args[2], args[3]);
    	new AWSCodeCommitHttpCredentials("techsophy.com_AWSPAss", "https://git-codecommit.us-east-1.amazonaws.com/v1/repos/TestCommit", "AKIAJYKGSXA76M5BEADQ", "Oa7YlfGaEfCBSA2bZ0pfcy/KFv4LOwb++a3V9kQvCyQI5fpTtEatQzFCiF+keaIQ");
	}

    public AWSCodeCommitHttpCredentials(String orgName_proName,String httpUrl, String accessKey, String secret ) {
    	secret = getPasswordFromSCMRepo(orgName_proName, accessKey);
    	URL url;
        String dateStamp = null;
        byte[] signedRequest = null;
		try {
			url = new URL(httpUrl);
			String canonicalRequest = "GIT\n" + url.getPath() + "\n\n" + "host:" + url.getHost() + "\n\n" + "host\n";
	        MessageDigest digest = MessageDigest.getInstance("SHA-256");
	        byte[] hash = digest.digest(canonicalRequest.getBytes());

	        String[] split = StringUtils.split(url.getHost(), ".");
	        if (split.length < 3)
	            throw new RuntimeException("Can not detect region from " + httpUrl);

	        String region = split[1];
	        Date now = new Date();
	        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss");
	        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
	        dateStamp = dateFormat.format(now);
	        String shortDateStamp = dateStamp.substring(0, 8);
	        String service = "codecommit";
	        String toSign = "AWS4-HMAC-SHA256\n" + dateStamp + "\n" + shortDateStamp + "/" + region + "/" + service + "/aws4_request\n" + bytesToHex(hash);
	        signedRequest = sign(secret, shortDateStamp, region, service, toSign);
		} catch (MalformedURLException mfurle) {
			System.err.println(mfurle.getMessage());
			throw new RuntimeException(mfurle.getMessage(), mfurle);
		} catch (NoSuchAlgorithmException nsae) {
			System.err.println(nsae.getMessage());
			throw new RuntimeException(nsae.getMessage(), nsae);
		}
		this.userName = accessKey;
        this.password = dateStamp + "Z" + bytesToHex(signedRequest);
        this.httpUrl = httpUrl;
        this.orgName_proName = orgName_proName;
    	saveProperty();
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] HmacSHA256(String data, byte[] key) {
        byte[] macRes = null;
		try {
			String algorithm = "HmacSHA256";
	        Mac mac = Mac.getInstance(algorithm);
			mac.init(new SecretKeySpec(key, algorithm));
			macRes = mac.doFinal(data.getBytes("UTF8"));
		} catch (NoSuchAlgorithmException nsae) {
			System.err.println(nsae.getMessage());
			throw new RuntimeException(nsae.getMessage(), nsae);
		} catch (InvalidKeyException ike) {
			System.err.println(ike.getMessage());
			throw new RuntimeException(ike.getMessage(), ike);
		} catch (IllegalStateException ise) {
			System.err.println(ise.getMessage());
			throw new RuntimeException(ise.getMessage(), ise);
		} catch (UnsupportedEncodingException usee) {
			System.err.println(usee.getMessage());
			throw new RuntimeException(usee.getMessage(), usee);
		}
		return macRes;
    }

    private static byte[] sign(String key, String dateStamp, String regionName, String serviceName, String toSign) {
    	byte[] signedRequest = null;
		try {
			byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
			byte[] kDate = HmacSHA256(dateStamp, kSecret);
	        byte[] kRegion = HmacSHA256(regionName, kDate);
	        byte[] kService = HmacSHA256(serviceName, kRegion);
	        byte[] kSigning = HmacSHA256("aws4_request", kService);
	        signedRequest = HmacSHA256(toSign, kSigning);
		} catch (UnsupportedEncodingException usee) {
			System.err.println(usee.getMessage());
			throw new RuntimeException(usee.getMessage(), usee);
		}
		return signedRequest;
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }
    

/**
 * @author Vishal
 *
 */
    public void saveProperty(){
    	String filePath = System.getenv("RBA_HOME")+File.separator+"buildagent"+File.separator+"automation-scripts"+File.separator+orgName_proName+File.separator+"awscredentials.properties";
    	Properties properties = new Properties();
    	properties.setProperty("aws.user", userName);
		properties.setProperty("aws.password",password);
		File file = new File(filePath);
		FileOutputStream fileOut;
		try {
			fileOut = new FileOutputStream(file);
			properties.store(fileOut, "awscredentials");
			fileOut.close();
		} catch (FileNotFoundException fnf) {
			System.err.println(fnf.getMessage());
		} catch (IOException io) {
			System.err.println(io.getMessage());
		}
		System.out.println("File awscredentials.properties saved!");
	}
    
   
    
    public String getPasswordFromSCMRepo(String orgName_proName,String accessKey){
    	DocumentBuilderFactory docFactory = null;
    	DocumentBuilder docBuilder =null;
    	XPath xPath=null;
    	Document doc ;
    	Element rootEle,ele=null;
    	
    	String arr[]= orgName_proName.split("_");
    	String scmRepo = System.getProperty("user.home") + File.separator + ".rabit" + File.separator + "org" + File.separator + arr[0] + File.separator + "scm" + File.separator + "scmrepositories.xml";
    	try {
    		docFactory = DocumentBuilderFactory.newInstance();
    		docBuilder = docFactory.newDocumentBuilder();
    		xPath =  XPathFactory.newInstance().newXPath();
			doc= docBuilder.parse(new File(scmRepo));
			rootEle = doc.getDocumentElement();
			ele = (Element) xPath.compile(".//repository[@username='"+accessKey+"']").evaluate(rootEle, XPathConstants.NODE);
			return ele.getAttribute("password");
    	} catch (ParserConfigurationException pce) {
    		System.err.println(pce.getMessage());
    		throw new RuntimeException(pce.getMessage(), pce);
    	} catch (SAXException sax) {
    		  System.err.println(sax.getMessage());
    	} catch (IOException ioe) {
    		  System.err.println(ioe.getMessage());
	    } catch (XPathExpressionException xpee) {
    		  System.err.println(xpee.getMessage());
	    }
		return null;
    	
    	 
    }
    
    
    public void saveCredential() {
    	String arr []= orgName_proName.split("_");
    	String filePath = System.getProperty("user.home") + File.separator + ".rabit" + File.separator + "org" + File.separator + arr[0] + File.separator + "scm" + File.separator + "awscredentials.xml";
    	File file= new File(filePath);
    	DocumentBuilderFactory docFactory = null;
    	DocumentBuilder docBuilder =null;
    	XPath xPath=null;
    	Document doc ;
    	Element rootEle,ele=null;
    	try {
    		docFactory = DocumentBuilderFactory.newInstance();
    		docBuilder = docFactory.newDocumentBuilder();
    		xPath =  XPathFactory.newInstance().newXPath();
    		if(!file.exists()){
    			doc = docBuilder.newDocument();
    			rootEle = doc.createElement("credentials");
    			ele= doc.createElement("credential");
    			ele.setAttribute("url", httpUrl);
    			ele.setAttribute("username", userName);
    			ele.setAttribute("password",password);
    			rootEle.appendChild(ele);
    			doc.appendChild(rootEle);
    		} else {
    			doc= docBuilder.parse(file);
    			rootEle = doc.getDocumentElement();
    			ele = (Element) xPath.compile("./credential[@username='"+userName+"']").evaluate(rootEle, XPathConstants.NODE);
    			if(ele!=null){
    				ele.setAttribute("url",httpUrl);
    				ele.setAttribute("username", userName);
        			ele.setAttribute("password",password);
    			} else {
    				ele = doc.createElement("credential");
        			ele.setAttribute("url", httpUrl);
        			ele.setAttribute("username", userName);
        			ele.setAttribute("password",password);
        			rootEle.appendChild(ele);        		
    			}
    		}
    		TransformerFactory transformerFactory = TransformerFactory.newInstance();
    		Transformer transformer = transformerFactory.newTransformer();
    		DOMSource source = new DOMSource(doc);
    		StreamResult result = new StreamResult(file);
    		transformer.transform(source, result);
    		System.out.println("File awscredentials.xml saved!");

    	  } catch (ParserConfigurationException pce) {
    		System.err.println(pce.getMessage());
    		throw new RuntimeException(pce.getMessage(), pce);
    	  } catch (TransformerException tfe) {
    		System.err.println(tfe.getMessage());
    	  } catch (SAXException sax) {
    		  System.err.println(sax.getMessage());
    	  } catch (IOException ioe) {
    		  System.err.println(ioe.getMessage());
    	  } catch (XPathExpressionException xpee) {
    		  System.err.println(xpee.getMessage());
    	  }
     }
}
