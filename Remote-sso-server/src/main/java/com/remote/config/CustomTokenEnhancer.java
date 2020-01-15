package com.remote.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

public class CustomTokenEnhancer implements TokenEnhancer {
   @Override
    public OAuth2AccessToken enhance(
      OAuth2AccessToken accessToken, 
      OAuth2Authentication authentication) {
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(
          "organization", authentication.getName()+"ramana");
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(
          additionalInfo);
        return accessToken;
    }
	
	/*@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		
	     OAuth2RefreshToken oAuth2RefreshToken = accessToken.getRefreshToken();

	     String refreshToken = "";

	     JsonParser objectMapper = JsonParserFactory.create();
	     Map<String, Object> claims = objectMapper.parseMap(JwtHelper.decode(oAuth2RefreshToken.getValue().getClaims()));
	     if(claims.containsKey("TOKEN_ID")) {
	        refreshToken = claims.get("TOKEN_ID").toString();
	     }

	     DefaultOAuth2RefreshToken defaultOAuth2RefreshToken = new DefaultOAuth2RefreshToken(refreshToken);
	     DefaultOAuth2AccessToken defaultOAuth2AccessToken = new DefaultOAuth2AccessToken(accessToken);
	     defaultOAuth2AccessToken.setRefreshToken(defaultOAuth2RefreshToken);

	     return super.enhance(defaultOAuth2AccessToken, authentication);
	     
	}*/
}