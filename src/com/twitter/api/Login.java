package com.twitter.api;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Servlet implementation class LoginServlet
 */

public class Login extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public Login() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		
		ConsumerAuthenticationEntity consumerAuthEntity = new ConsumerAuthenticationEntity();
		UserAuthenticationEntity userAuthEntity = new UserAuthenticationEntity();
		
		OAuthProcessor oAuthProcessor = new OAuthProcessor(consumerAuthEntity, userAuthEntity);
		
		String oAuthHeader = oAuthProcessor.getOauthHeader("https://api.twitter.com/oauth/request_token", "POST");
		
		HttpsURLConnection  connection = (HttpsURLConnection)new URL("https://api.twitter.com/oauth/request_token").openConnection();
	    connection.setDoOutput(true);	
	    connection.setDoInput(true);	
	    connection.setRequestMethod("POST");    
	    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		connection.setRequestProperty("Authorization:", oAuthHeader);

		
		
		try{
		    OutputStreamWriter wr = new OutputStreamWriter (
                connection.getOutputStream ());
			//wr.write(oAuthHeader);
			wr.flush ();
			wr.close ();
						
		
		InputStream is = connection.getInputStream();
		
		BufferedReader rd = new BufferedReader(new InputStreamReader(is));
	      String line;
	      while((line = rd.readLine()) != null) {
	        System.out.println(line);
	      }
	      
	      rd.close();
	      
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		
	}

}
