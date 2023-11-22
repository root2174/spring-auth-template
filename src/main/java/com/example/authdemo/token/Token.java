package com.example.authdemo.token;

import com.example.authdemo.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {

	@Id
	@GeneratedValue
	private Integer id;
	private String tokenValue;

	@Enumerated(EnumType.STRING)
	private TokenType tokenType;

	private boolean expired;
	private boolean revoked;

	@ManyToOne
	@JoinColumn(name = "user_id")
	private User user;

}
