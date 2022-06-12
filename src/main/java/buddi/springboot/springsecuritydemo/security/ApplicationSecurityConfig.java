package buddi.springboot.springsecuritydemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static buddi.springboot.springsecuritydemo.security.ApplicationUserPermission.*;
import static buddi.springboot.springsecuritydemo.security.ApplicationUserRoles.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

//authentication for request
    @Override
    protected void configure(HttpSecurity http) throws Exception {
       http
               .csrf().disable()
               .authorizeHttpRequests()
               .antMatchers("/", "index", "/css/*", "js/*").permitAll()
               .antMatchers("/api/**").hasRole(STUDENT.name())
               //define authority and permissions
               .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermissioons())
               .antMatchers(HttpMethod.POST,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermissioons())
               .antMatchers(HttpMethod.PUT,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermissioons())
               .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINISTRATOR.name())
               .anyRequest()
               .authenticated()
               .and()
               .httpBasic();
    }
// create user
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {

       UserDetails userbuddi =  User.builder()
                .username("buddinipun")
                .password(passwordEncoder.encode("password"))
             //   .roles(STUDENT.name())
               .authorities(STUDENT.getgrantedAuthorities())
               .build();

       UserDetails usernipun = User.builder()
               .username("nipun")
               .password(passwordEncoder.encode("password123"))
              // .roles(ADMIN.name())
               .authorities(ADMIN.getgrantedAuthorities())
               .build();

       UserDetails usertom = User.builder()
               .username("tom")
               .password(passwordEncoder.encode("password"))
              // .roles(ADMINISTRATOR.name())
               .authorities(ADMINISTRATOR.getgrantedAuthorities())
               .build();

       return new InMemoryUserDetailsManager(userbuddi,usernipun,usertom);
    }
}
