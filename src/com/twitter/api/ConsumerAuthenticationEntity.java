package com.twitter.api;

public class ConsumerAuthenticationEntity {


	private String consumerKey;
	
	private String consumerSecret;
	

	public String getConsumerKey() {
		return consumerKey;
	}
   
	public void setConsumerKey(String key) {
		this.consumerKey = key;
	}

	public String getConsumerSecret() {
		return consumerSecret;
	}

	public void setConsumerSecret(String secret) {
		this.consumerSecret = secret;
	}
	
}
