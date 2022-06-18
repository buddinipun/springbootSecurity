package buddi.springboot.springsecuritydemo.auth;

import org.springframework.stereotype.Component;

import java.util.Optional;

public interface ApplicationUserDao {

   public Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
