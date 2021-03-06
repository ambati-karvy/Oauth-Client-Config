package com.remote.config;

import java.util.Calendar;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.ClientTokenServices;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Service;

@Service
public class OAuth2ClientTokenSevices implements ClientTokenServices {
    //@formatter:off

    @Autowired
    private SettingsRepository settings;

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication) {
    	
    	
        String accessToken = settings.getAccessToken();
        String refreshToken = settings.getRefreshToken();
        Calendar expirationDate = settings.getExpiresIn();

        if (accessToken == null) return null;

        DefaultOAuth2AccessToken oAuth2AccessToken = new DefaultOAuth2AccessToken(accessToken);
        oAuth2AccessToken.setExpiration(expirationDate.getTime());
        oAuth2AccessToken.setRefreshToken(new DefaultOAuth2RefreshToken(refreshToken));
        

        return oAuth2AccessToken;
    }

    @Override
    public void saveAccessToken(OAuth2ProtectedResourceDetails resource,
            Authentication authentication, OAuth2AccessToken accessToken) {
    	
        Calendar expirationDate = Calendar.getInstance();
        expirationDate.setTime(accessToken.getExpiration());

        settings.setAccessToken(accessToken.getValue());
        settings.setExpiresIn(expirationDate);
        settings.setRefreshToken(accessToken.getRefreshToken().getValue());
    }

    @Override
    public void removeAccessToken(OAuth2ProtectedResourceDetails resource,
            Authentication authentication) {
    	
        settings.setAccessToken(null);
        settings.setExpiresIn(null);
        settings.setRefreshToken(null);
    }

    //@formatter:on
}