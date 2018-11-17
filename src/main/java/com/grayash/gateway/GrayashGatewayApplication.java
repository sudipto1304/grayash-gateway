package com.grayash.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})
@EnableZuulProxy
@RestController
public class GrayashGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(GrayashGatewayApplication.class, args);
	}
}
