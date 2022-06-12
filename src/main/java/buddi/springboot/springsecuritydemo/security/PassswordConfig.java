package buddi.springboot.springsecuritydemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PassswordConfig {

    @Bean
    public PasswordEncoder passwordEncorder(){
        return new BCryptPasswordEncoder(10);
    }
}
