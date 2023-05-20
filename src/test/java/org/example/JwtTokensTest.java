package org.example;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;

public class JwtTokensTest {

    @Test
    void whenProvidedPlainKey_thenThrowsException() {
        String token = Jwts.builder()
          .addClaims(new HashMap<>(Map.of("sub", "1")))
          .addClaims(new HashMap<>(Map.of("iat", "19232193192")))
          .setHeader(new HashMap<>(Map.of("alg", "HS256")))
          .setHeader(new HashMap<>(Map.of("typ", "JWT")))
          .signWith(SignatureAlgorithm.HS384, Base64.getEncoder().encode("12345".getBytes(StandardCharsets.UTF_8)))
          .compact();

        Assertions.assertThatThrownBy(() -> Jwts.parser()
          .setSigningKey("12345".getBytes(StandardCharsets.UTF_8))
          .parseClaimsJws(token)).isInstanceOf(SignatureException.class);
    }

    @Test
    void whenProvidedBase64Key_thenParsedJustFine() {
        String token = Jwts.builder()
          .addClaims(new HashMap<>(Map.of("sub", "1")))
          .addClaims(new HashMap<>(Map.of("iat", "19232193192")))
          .setHeader(new HashMap<>(Map.of("alg", "HS256")))
          .setHeader(new HashMap<>(Map.of("typ", "JWT")))
          .signWith(SignatureAlgorithm.HS384, Base64.getEncoder().encode("12345".getBytes(StandardCharsets.UTF_8)))
          .compact();

        Assertions.assertThat(
          Jwts.parser()
          .setSigningKey(Base64.getEncoder().encode("12345".getBytes(StandardCharsets.UTF_8)))
          .parseClaimsJws(token).getBody()
        ).containsEntry("sub", "1");
    }

}