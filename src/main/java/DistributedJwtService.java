import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.ArrayList;
import java.util.Date;

public class DistributedJwtService
{
    private String secretKey;
    private Key key;
    private long expiredTime;
    private SignatureAlgorithm alg;

    public DistributedJwtService(String secretKey, long expiredTime, SignatureAlgorithm alg)
    {
        this.secretKey = secretKey;

        String secretKeyEncodeBase64 = Encoders.BASE64.encode(secretKey.getBytes());
        byte[] keyBytes = Decoders.BASE64.decode(secretKeyEncodeBase64);

        this.key = Keys.hmacShaKeyFor(keyBytes);

        this.expiredTime = expiredTime;
        this.alg = alg;
    }

    public ArrayList<String> createToken(String userPk)
    {
        String token = createJwtToken(userPk);

        ArrayList<String> result = new ArrayList<>();
        result.add(token);

        return result;
    }

    private String createJwtToken(String userPk)
    {
        Claims claims = Jwts.claims().setSubject(userPk);
        Date now = new Date();

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expiredTime) )
                .signWith(key, alg)
                .compact();

        return token;
    }
}
