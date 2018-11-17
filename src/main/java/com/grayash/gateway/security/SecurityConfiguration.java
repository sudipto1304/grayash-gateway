package com.grayash.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.grayash.gateway.filter.JWTFilter;
import com.grayash.gateway.filter.TokenProvider;


@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    public final static String AUTHORIZATION_HEADER = "Authorization";

    @Autowired
    private TokenProvider tokenProvider;

//    @Autowired
//    private AuthenticationProvider authenticationProvider;
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(this.authenticationProvider);
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        JWTFilter customFilter = new JWTFilter(this.tokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class)
        .authorizeRequests()
                .antMatchers("/statuscheck").permitAll()
                .anyRequest().authenticated();
        http.csrf().disable();

    }
}
