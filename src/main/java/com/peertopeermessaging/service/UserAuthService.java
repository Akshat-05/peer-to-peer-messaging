package com.peertopeermessaging.service;

import com.peertopeermessaging.entity.UserDetails;
import com.peertopeermessaging.exception.ApplicationException;
import com.peertopeermessaging.repository.UserDetailsRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

@Log4j2
@Service
public class UserAuthService {

    @Value("${spring.secret.jwt}")
    private String jwtSecret;

    @Autowired
    private UserDetailsRepository repository;

    public String isValid(String authorization) throws ApplicationException {
        if (authorization != null && authorization.toLowerCase().startsWith("basic")) {
            // Authorization: Basic base64credentials
            String base64Credentials = authorization.substring("Basic".length()).trim();
            byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(credDecoded, StandardCharsets.UTF_8);
            // credentials = username:password
            String[] values = credentials.split(":", 2);
            Optional<UserDetails> user = repository.findById(values[0]);
            if (user.isPresent() && user.get().getPassword().equals(values[1])) {
                return generateToken(values[0]);
            }
        }
        throw new ApplicationException("invalid user");
    }

    private String generateToken(String userName) {
        Key hmacKey = new SecretKeySpec(Base64.getDecoder().decode(jwtSecret),
                SignatureAlgorithm.HS256.getJcaName());
        return Jwts.builder()
                .claim("userName", userName)
                .expiration(Date.from(new Date().toInstant().plusSeconds(600)))
                .claim("ttl", Instant.now().plusSeconds(86400).toEpochMilli())
                .signWith(hmacKey, SignatureAlgorithm.HS256)
                .compact();
    }

    private void authorized(String token) throws ApplicationException {
        if (StringUtils.isNotBlank(token)) {
            Key hmacKey = new SecretKeySpec(Base64.getDecoder().decode(jwtSecret),
                    SignatureAlgorithm.HS256.getJcaName());
            Jws<Claims> jws = null;
            try {
                jws = Jwts.parser().setSigningKey(hmacKey).build().parseClaimsJws(token);
            } catch (Exception e) {
                log.info("Invalid jwt token", e.getMessage());
                throw new ApplicationException("Invalid jwt token");
            }
            if (jws == null || jws.getPayload().getExpiration().after(Date.from(new Date().toInstant()))) {
                throw new ApplicationException("expired jwt token");
            }
        }
    }

}