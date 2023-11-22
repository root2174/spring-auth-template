package com.example.authdemo.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Integer> {

	@Query("""
    SELECT t FROM Token t
    inner join User u on t.user.id = u.id
    where u.id = :userId and t.expired = false and t.revoked = false
    """)
	List<Token> findAllValidTokensByUser(Integer userId);

	Optional<Token> findByTokenValue(String tokenValue);
}
