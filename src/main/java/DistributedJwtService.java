import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import javax.servlet.http.Cookie;
import java.security.Key;
import java.util.Date;

public class DistributedJwtService
{
    private String secretKey;
    private Key key;
    private long expiredTime;
    private SignatureAlgorithm alg;

    class Token
    {
        String cookieToken;
        String bodyToken;

        public Token(String cookieToken, String bodyToken) {
            this.cookieToken = cookieToken;
            this.bodyToken = bodyToken;
        }

        /**
         * This Function returns Cookie object.
         * Name is "jwt", HttpOnly, Path(/)
         *
         * Example is below
         * *****************
         * Just You need to add cookie
         * response.addCookie(token.getCookieToken());
         * ******************
         * @return javax cookie object
         */
        public Cookie getCookieToken() {
            Cookie cookie = new Cookie("jwt", cookieToken);
            cookie.setPath("/");
            cookie.setHttpOnly(true);

            return cookie;
        }

        public String getBodyToken() {
            return bodyToken;
        }
    }

    public DistributedJwtService(String secretKey, long expiredTime, SignatureAlgorithm alg)
    {
        this.secretKey = secretKey;

        String secretKeyEncodeBase64 = Encoders.BASE64.encode(secretKey.getBytes());
        byte[] keyBytes = Decoders.BASE64.decode(secretKeyEncodeBase64);

        this.key = Keys.hmacShaKeyFor(keyBytes);

        this.expiredTime = expiredTime;
        this.alg = alg;
    }

    public Token createToken(String userPk)
    {
        // issue token
        String token = createJwtToken(userPk);

        // divide token
        Token dividedJWTToken = divideJWTIntoField(token);

        return dividedJWTToken;
    }

    private Token divideJWTIntoField(String token)
    {
        String[] temp = token.split("\\.");

        if (temp.length != 3)
        {
            throw new RuntimeException("Problem with dividing token");
        }

        Token divideToken = new Token(temp[0] + "." + temp[1],
                                        temp[2]);
        return divideToken;
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
