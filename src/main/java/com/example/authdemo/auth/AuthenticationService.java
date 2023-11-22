package com.example.authdemo.auth;

import com.example.authdemo.config.JwtService;
import com.example.authdemo.token.Token;
import com.example.authdemo.token.TokenRepository;
import com.example.authdemo.token.TokenType;
import com.example.authdemo.user.Role;
import com.example.authdemo.user.User;
import com.example.authdemo.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	private final TokenRepository tokenRepository;

	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
		);

		var user = userRepository.findByEmail(request.getEmail())
				.orElseThrow();

		revokeAllUserTokens(user);

		var jwtToken = jwtService.generateToken(user);

		saveUserToken(user, jwtToken);

		return AuthenticationResponse.builder()
				.token(jwtToken)
				.build();
	}

	public AuthenticationResponse register(RegisterRequest request) {
		User user = User.builder()
				.email(request.getEmail())
				.password(passwordEncoder.encode(request.getPassword()))
				.firstName(request.getFirstName())
				.lastName(request.getLastName())
				.role(Role.USER)
				.build();

		User savedUser = userRepository.save(user);

		var jwtToken = jwtService.generateToken(user);

		revokeAllUserTokens(savedUser);

		saveUserToken(savedUser, jwtToken);

		return AuthenticationResponse.builder()
				.token(jwtToken)
				.build();
	}

	private void revokeAllUserTokens(User user) {
		var tokens = tokenRepository.findAllValidTokensByUser(user.getId());

		if (tokens.isEmpty()) {
			return;
		}

		tokens.forEach(token -> {
			token.setRevoked(true);
			token.setExpired(true);
		});

		tokenRepository.saveAll(tokens);
	}

	private void saveUserToken(User user, String jwtToken) {
		var token = Token.builder()
				.user(user)
				.tokenValue(jwtToken)
				.tokenType(TokenType.BEARER)
				.revoked(false)
				.expired(false)
				.build();
		tokenRepository.save(token);
	}
}
