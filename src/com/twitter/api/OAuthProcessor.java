package com.twitter.api;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class OAuthProcessor {
	
	private static final String SIGNATURE_METHOD = "HMAC-SHA1";
    private static final String VERSION = "1.0";
    private static final String OAUTH = "oauth_";
    private static final String AND = "&";
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
  
    private Map<String, String> headerParameters;
    private Map<String, String> signingKey;
    
    public OAuthProcessor(ConsumerAuthenticationEntity consumerAuthEntity, UserAuthenticationEntity userAuthEntity)
    {
    	headerParameters = new LinkedHashMap<String, String>();
    	
    	//headerParameters.put("oauth_callback", "TrendingTweets");
    	headerParameters.put("oauth_consumer_key", consumerAuthEntity.getConsumerKey());
    	headerParameters.put("oauth_nonce", getNonce());
    	headerParameters.put("oauth_signature", "");
    	headerParameters.put("oauth_signature_method", SIGNATURE_METHOD);
    	headerParameters.put("oauth_timestamp", getTimeStamp());
    	headerParameters.put("oauth_token", userAuthEntity.getAccessToken());
    	headerParameters.put("oauth_version", VERSION);
    	
    	
    	signingKey = new HashMap<String, String>();
    	signingKey.put("oauth_consumer_key_secret", consumerAuthEntity.getConsumerSecret());
    	signingKey.put("oauth_token_secret", userAuthEntity.getAccessTokenSecret());
    	
    }
    
    
    private String getOAuthHeaderParameters(String url, String method)
    {
    	
    	StringBuilder keyValuePairs = new StringBuilder();
    	
    	Iterator it = headerParameters.entrySet().iterator();
    	
    	while(it.hasNext())
    	{
    		
    		Map.Entry<String, String> entry = (Entry<String, String>) it.next();
    		String key = entry.getKey();
    		String value = entry.getValue();
    		
    		if(key.equals("oauth_signature"))
    		{
    			value = calculateSignature(url, method);
    		}

    		if(value != null)
    		{
    		  keyValuePairs.append(getEncodedString(key));
    		  keyValuePairs.append("=\"");
    		  keyValuePairs.append(getEncodedString(value));
    		  keyValuePairs.append("\", ");    		
    		}
    	}
    	
    	String retVal = keyValuePairs.toString();
    	
    	return retVal.substring(0, retVal.length()-2);
    	
    }
    
    public String getOauthHeader(String url, String method)
    {
    	StringBuilder oAuthHeader = new StringBuilder();
    	
    	//add 'OAuth' to the header
    	oAuthHeader.append("OAuth ");
    	
    	//create the parameter string to be appended to the OAuth header
    	oAuthHeader.append(getOAuthHeaderParameters(url, method));
    	
    	return oAuthHeader.toString();
    	
    }
    
    private String getNonce()
    {
    	StringBuilder nonce = new StringBuilder();
    	Random random = new Random();
    	
    	for(int i = 0; i < 32; i++ )
    	{
    		if( i < 16)
    			nonce.append((char)(random.nextInt(10)+48));
    		else
    			nonce.append((char)(random.nextInt(26)+97));
    	}
    	    	
    	return nonce.toString();
    }
    
    private String getTimeStamp()
    {
    	long unixTime = (System.currentTimeMillis()/1000L);    	
    	return String.valueOf(unixTime);
    }
    
    
    private String getEncodedString(String input)
    {
    	String encodedString = null;
    	
    	try {
			encodedString = URLEncoder.encode(input, "UTF-8");
		
    	} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	return encodedString;
    }
    
    private String getParameterString()
    {
    	Iterator it = headerParameters.entrySet().iterator();
    	
    	StringBuilder parameterString = new StringBuilder();
    	
    	while(it.hasNext())
    	{
    		Map.Entry<String, String> entry = (Entry<String, String>)it.next();
    		
    		if(!entry.getKey().equals("oauth_signature") && (entry.getValue() != null)) //don't add oauth signature. Also, don't add oauth access token when we dont have one
    		{
    		  parameterString.append(entry.getKey());
    		  parameterString.append("=");
    		  parameterString.append(entry.getValue());
    		  parameterString.append(AND);  		
    		}
    	}
    	
    	String retVal = parameterString.toString();
    	
    	return retVal.substring(0, retVal.length()-1);
    	
    }
    
    private String getSignatureBase(String url, String method)
    {
    	
    	StringBuilder signatureBase = new StringBuilder();
    	   	
    	
    	//add method to the signature base
    	signatureBase.append(method.toUpperCase());
    	signatureBase.append(AND);
    	
    	
    	//add encoded Url to the signature base
    	signatureBase.append(getEncodedString(url));
    	signatureBase.append(AND);
    	
    	
    	//generate the parameter string
    	String parameterString = getParameterString();
    	
    	//add encoded parameter string to the signature base
    	signatureBase.append(getEncodedString(parameterString));
    	
    	    	
    	return signatureBase.toString();
    	
    }
    
    private String getSigningKey()
    {
    	
    	Iterator it = signingKey.entrySet().iterator();
    	StringBuilder hashKey = new StringBuilder();
    	
    	while(it.hasNext())
    	{
    		Map.Entry<String, String> entry = (Entry<String, String>) it.next();
    		
    		String val = entry.getValue();
    		
    		if(val != null)
    		  hashKey.append(getEncodedString(entry.getValue()));
    		
    		hashKey.append(AND);    		
    	}
    	
    	String retVal = hashKey.toString();
    	
    	return retVal.substring(0, retVal.length()-1);
    	
    }
    
    
    private static String calculateHMACSHA1(String data, String key)throws java.security.SignatureException
    {
    	String result;
    	try {

    		// get an hmac_sha1 key from the raw key bytes
    		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);

    		// get an hmac_sha1 Mac instance and initialize with the signing key
    		Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
    		mac.init(signingKey);

    		// compute the hmac on input data bytes
    		byte[] rawHmac = mac.doFinal(data.getBytes());

    		// base64-encode the hmac
    		result = Base64.encode(rawHmac);

    	} catch (Exception e) {
    		throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
    	}
    	return result;
    }
	    
    
    private String calculateSignature(String url, String method)
    {
    	//calculate the signature base
    	String signatureBase = getSignatureBase(url, method);
    	
    	//get the signing key
    	String hashKey = getSigningKey();
    	
    	//calculate the signature
    	String signature = null;
		try {
			signature = calculateHMACSHA1(signatureBase, hashKey);
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	return signature;
    }
}
