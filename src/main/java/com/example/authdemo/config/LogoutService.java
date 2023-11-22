package com.example.authdemo.config;

import com.example.authdemo.token.Token;
import com.example.authdemo.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

	private final TokenRepository tokenRepository;
	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		final String authHeader = request.getHeader("Authorization");

		if (!hasToken(authHeader)) {
			return;
		}

		final String jwt = extractJwt(authHeader);

		Token storedToken = tokenRepository.findByTokenValue(jwt).orElse(null);

		if (storedToken != null) {
			storedToken.setRevoked(true);
			storedToken.setExpired(true);

			tokenRepository.save(storedToken);
		}
	}
	private String extractJwt(String authHeader) {
		return authHeader.substring(7);
	}
	private boolean hasToken(String authHeader) {
		return authHeader != null && authHeader.startsWith("Bearer ");
	}
}
