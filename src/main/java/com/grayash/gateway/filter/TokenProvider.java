package com.grayash.gateway.filter;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class TokenProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";


    @Value("${spring.security.authentication.jwt.secret}")
    private String secretKey;


    public Authentication getAuthentication(String token) {
        final String SECRET1 = Base64.getEncoder().encodeToString(this.secretKey.getBytes());
        Claims claims = Jwts.parser().setSigningKey(SECRET1).parseClaimsJws(token).getBody();
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();
        grantedAuthorities.add(new SimpleGrantedAuthority("CUSTOMER"));
        User principal = new User(claims.get("user_name").toString(), "", grantedAuthorities);
        return new UsernamePasswordAuthenticationToken(principal, "", grantedAuthorities);
    }

    public boolean validateToken(String authToken) {
        final String SECRET1 = Base64.getEncoder().encodeToString(this.secretKey.getBytes());
        Claims claims = Jwts.parser().setSigningKey(SECRET1).parseClaimsJws(authToken).getBody();

        return true;
    }
}
