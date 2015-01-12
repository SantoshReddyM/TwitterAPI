package com.twitter.api;

public class UserAuthenticationEntity {

	private String accessToken;
	
	private String accessTokenSecret;
	
	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = "";
	}

	public String getAccessTokenSecret() {
		return accessTokenSecret;
	}

	public void setAccessTokenSecret(String accessTokenSecret) {
		this.accessTokenSecret = "";
	}
	
}
