package com.example.authdemo.config;

import com.example.authdemo.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;
	private final TokenRepository tokenRepository;
	private final JwtHelper jwtHelper;
	@Override
	protected void doFilterInternal(
			@NonNull HttpServletRequest request,
			@NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain) throws ServletException, IOException {
		final String authHeader = request.getHeader("Authorization");

		if (!jwtHelper.hasToken(authHeader)) {
			filterChain.doFilter(request, response);
			return;
		}

		final String jwt = jwtHelper.extractJwt(authHeader);

		String userEmail = jwtService.extractUsername(jwt);

		if (hasUserEmail(userEmail) && !isAuthenticated()) {
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

			boolean isTokenValid = tokenRepository.findByTokenValue(jwt)
					.map(t -> !t.isExpired() && !t.isRevoked())
					.orElse(false);

			if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
								userDetails,
								null,
								userDetails.getAuthorities());

				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}

		filterChain.doFilter(request, response);
	}

	private boolean hasUserEmail(String userEmail) {
		return userEmail != null;
	}

	private boolean isAuthenticated() {
		return SecurityContextHolder.getContext().getAuthentication() != null;
	}
}
