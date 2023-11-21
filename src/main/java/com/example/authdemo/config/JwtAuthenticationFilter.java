package com.example.authdemo.config;

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
	@Override
	protected void doFilterInternal(
			@NonNull HttpServletRequest request,
			@NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain) throws ServletException, IOException {
		final String authHeader = request.getHeader("Authorization");

		if (!hasToken(authHeader)) {
			filterChain.doFilter(request, response);
			return;
		}

		final String jwt = extractJwt(authHeader);

		String userEmail = jwtService.extractUsername(jwt);

		if (hasUserEmail(userEmail) && !isAuthenticated()) {
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

			if (jwtService.isTokenValid(jwt, userDetails)) {
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

	private String extractJwt(String authHeader) {
		return authHeader.substring(7);
	}

	private boolean hasToken(String authHeader) {
		return authHeader != null && authHeader.startsWith("Bearer ");
	}

	private boolean hasUserEmail(String userEmail) {
		return userEmail != null;
	}

	private boolean isAuthenticated() {
		return SecurityContextHolder.getContext().getAuthentication() != null;
	}
}
