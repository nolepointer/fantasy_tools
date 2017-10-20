package com.fantasy.tools.fantasy_tools.com.fantasy.tools.oath;

import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.util.*;

public class YahooUserInfoTokenServices extends UserInfoTokenServices {

    public static final String USERID = "userid";
    public static final String USER_ROLE = "user";
    private String guid;
    private String clientId;

    public YahooUserInfoTokenServices(String userInfoEndpointUrl, String clientId) {
        super(userInfoEndpointUrl, clientId);
        this.clientId = clientId;
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {
        Map<String, Object> map = new HashMap<>();
        map.put(USERID, UUID.randomUUID().toString());
        Object principal = this.getPrincipal(map);
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(USER_ROLE);
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(grantedAuthority);
        OAuth2Request request = new OAuth2Request((Map)null, this.clientId, (Collection)null, true, (Set)null, (Set)null, (String)null, (Set)null, (Map)null);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(principal, "N/A", authorities);
        token.setDetails(map);
        return new OAuth2Authentication(request, token);
    }

    public void setGuid(String guid) {
        this.guid = guid;
    }

    public String getGuid() {
        return guid;
    }
}
