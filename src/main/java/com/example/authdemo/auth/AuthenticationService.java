package com.example.authdemo.auth;

import com.example.authdemo.config.JwtService;
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

	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
		);

		var user = userRepository.findByEmail(request.getEmail())
				.orElseThrow();

		var jwtToken = jwtService.generateToken(user);

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

		var jwtToken = jwtService.generateToken(user);
		userRepository.save(user);

		return AuthenticationResponse.builder()
				.token(jwtToken)
				.build();
	}
}
