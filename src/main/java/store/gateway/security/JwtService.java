package store.gateway;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;

@Service
public class JwtService {
    
    @Value("${store.jwt.secret-key}")
    private String secretKey;

    @Value("${store.jwt.issuer}")
    private String issuer;

    private SecretKey key;
    private JwtParser parser;

    @PostConstruct
    public void init(){
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
        this.parser = Jwts.parser().verifyWith(key).build();
    }

    public String getId(String token) {
        final Claims claims = resolveClaims(token);
        return claims.getId();
    }

    private Claims resolveClaims(String token) {
        if (token == null) throw new io.jsonwebtoken.MalformedJwtException("token is null");
        return validateClaims(parser.parseSignedClaims(token).getPayload());
    }

    private Claims validateClaims(Claims claims) throws ExpiredJwtException {
        if (claims.getExpiration().before(new Date())) throw new ExpiredJwtException(null, claims, issuer);
        if (claims.getNotBefore().after(new Date())) throw new ExpiredJwtException(null, claims, issuer);
        return claims;
    }

}
