import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

public class DistributedJwtServiceTest
{
    private String key = "secretsecretsecretsecretsecretsecretsecretsecretsecret";
    private long expiredTime = 1000L * 60 * 60;

    @Test
    public void issueToken()
    {

        DistributedJwtService instance = new DistributedJwtService(
                key, expiredTime, SignatureAlgorithm.HS256
        );

        DistributedJwtService.Token result = instance.createToken("33");

        assertThat(result.getCookieToken().getName() ).isEqualTo("jwt");
        assertThat(result.getCookieToken().getValue() ).isNotEmpty();
        assertThat(result.getCookieToken().getPath()).isEqualTo("/");
        assertThat(result.getCookieToken().isHttpOnly()).isTrue();
        assertThat(result.getBodyToken() ).isNotEmpty();
    }
}
