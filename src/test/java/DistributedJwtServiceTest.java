import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

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

        ArrayList<String> result = instance.createToken("33");


    }
}
