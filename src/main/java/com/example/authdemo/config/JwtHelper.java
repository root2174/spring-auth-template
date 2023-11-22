package com.example.authdemo.config;

import org.springframework.stereotype.Component;

@Component
public class JwtHelper {
	public String extractJwt(String authHeader) {
		return authHeader.substring(7);
	}
	public boolean hasToken(String authHeader) {
		return authHeader != null && authHeader.startsWith("Bearer ");
	}
}
