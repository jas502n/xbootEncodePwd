# xbootEncodePwd


```bash
xboot-activiti-1.0-SNAPSHOT  xboot-cms-1.0-SNAPSHOT       xboot-generator-1.0-SNAPSHOT
xboot-app-1.0-SNAPSHOT       xboot-core-1.0-SNAPSHOT      xboot-open-1.0-SNAPSHOT
xboot-autochat-1.0-SNAPSHOT  xboot-docking-1.0-SNAPSHOT   xboot-quartz-1.0-SNAPSHOT
xboot-base-1.0-SNAPSHOT      xboot-ems-1.0-SNAPSHOT       xboot-social-1.0-SNAPSHOT
xboot-bbs-1.0-SNAPSHOT       xboot-file-1.0-SNAPSHOT      xboot-your-1.0-SNAPSHOT
```

反编译，查找关键词 `$2a$10` 发现关键代码


```java
IlabXV2LoginController.class

String hashPass = bcryptPasswordEncoder.encode("123456");
boolean flag = bcryptPasswordEncoder.matches("123456", "$2a$10$zHF74Qh4w1csYc/Di49Wf.3ITtCBw.7yc84Cc9NRi3

MemberController.class
if (!bCryptPasswordEncoder.matches(truePassword, user.getPassword())) {
if (!bCryptPasswordEncoder.matches(truePassword, user.getPassword())) {
```

跟踪 BCryptPasswordEncoder() 方法来到  `spring-security-core-5.3.6.RELEASE.jar/org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder`

mvn pom.xml

```xml
<!-- https://mvnrepository.com/artifact/org.springframework.security/spring-security-core -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-core</artifactId>
    <version>5.3.6.RELEASE</version>
</dependency>

```

xbootPwdEncode.java

```java
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class xbootPwdEncode implements PasswordEncoder {
    private Pattern BCRYPT_PATTERN;
    private final Log logger;
    private final int strength;
    private final BCryptPasswordEncoder.BCryptVersion version;
    private final SecureRandom random;

    public xbootPwdEncode() {
        this(-1);
    }

    public xbootPwdEncode(int strength) {
        this(strength, (SecureRandom) null);
    }

    public xbootPwdEncode(BCryptPasswordEncoder.BCryptVersion version) {
        this(version, (SecureRandom) null);
    }

    public xbootPwdEncode(BCryptPasswordEncoder.BCryptVersion version, SecureRandom random) {
        this(version, -1, random);
    }

    public xbootPwdEncode(int strength, SecureRandom random) {
        this(BCryptPasswordEncoder.BCryptVersion.$2A, strength, random);
    }

    public xbootPwdEncode(BCryptPasswordEncoder.BCryptVersion version, int strength) {
        this(version, strength, (SecureRandom) null);
    }

    public xbootPwdEncode(BCryptPasswordEncoder.BCryptVersion version, int strength, SecureRandom random) {
        this.BCRYPT_PATTERN = Pattern.compile("\\A\\$2(a|y|b)?\\$(\\d\\d)\\$[./0-9A-Za-z]{53}");
        this.logger = LogFactory.getLog(this.getClass());
        if (strength == -1 || strength >= 4 && strength <= 31) {
            this.version = version;
            this.strength = strength == -1 ? 10 : strength;
            this.random = random;
        } else {
            throw new IllegalArgumentException("Bad strength");
        }
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        } else {
            String salt;
            if (this.random != null) {
                salt = BCrypt.gensalt(this.version.getVersion(), this.strength, this.random);
            } else {
                salt = BCrypt.gensalt(this.version.getVersion(), this.strength);
            }

            return BCrypt.hashpw(rawPassword.toString(), salt);
        }
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        } else if (encodedPassword != null && encodedPassword.length() != 0) {
            if (!this.BCRYPT_PATTERN.matcher(encodedPassword).matches()) {
                this.logger.warn("Encoded password does not look like BCrypt");
                return false;
            } else {
                return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
            }
        } else {
            this.logger.warn("Empty encoded password");
            return false;
        }
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        if (encodedPassword != null && encodedPassword.length() != 0) {
            Matcher matcher = this.BCRYPT_PATTERN.matcher(encodedPassword);
            if (!matcher.matches()) {
                throw new IllegalArgumentException("Encoded password does not look like BCrypt: " + encodedPassword);
            } else {
                int strength = Integer.parseInt(matcher.group(2));
                return strength < this.strength;
            }
        } else {
            this.logger.warn("Empty encoded password");
            return false;
        }
    }

    public static enum BCryptVersion {
        $2A("$2a"),
        $2Y("$2y"),
        $2B("$2b");

        private final String version;

        private BCryptVersion(String version) {
            this.version = version;
        }

        public String getVersion() {
            return this.version;
        }
    }

    public static void main(String[] args) {
        // 加密单个密码，Example: $2a$10$ClRDFgxsGy78DcSi5kE8Zeu.jAfOlxxsqixMd7bsoP4enr.Msd1MC
        System.out.println(new xbootPwdEncode().encode("123456"));
        // 当前加密的密码是否和明文密码匹配成功，输出布尔类型值 true
        System.out.println(new xbootPwdEncode().matches("123456", "$2a$10$7PocfErZodpsp8rK7j8nv.RK1Hn783EyU2YIowuTZkPQdjatp9riK"));


    }
}

```

![image](https://user-images.githubusercontent.com/16593068/148507655-80404c59-cfad-464f-97ac-a93f894a03c4.png)

参考链接：https://en.wikipedia.org/wiki/Bcrypt

```
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
\__/\/ \____________________/\_____________________________/
Alg Cost      Salt                        Hash
```

