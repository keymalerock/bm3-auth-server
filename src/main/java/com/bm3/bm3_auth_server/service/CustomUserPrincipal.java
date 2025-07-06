package com.bm3.bm3_auth_server.service;

import com.bm3.bm3_auth_server.entity.Permission;
import com.bm3.bm3_auth_server.entity.Rol;
import com.bm3.bm3_auth_server.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Data
@AllArgsConstructor
public class CustomUserPrincipal implements UserDetails {
    private Long id;
    private String username;
    private String email;
    private String password;
    private boolean enabled;
    private Collection<? extends GrantedAuthority> authorities;

    public static CustomUserPrincipal create(User user) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        // Agregar roles como authorities
        for (Rol role : user.getRolesMtM()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));

            // Agregar permisos específicos
            for (Permission permission : role.getPermissions()) {
                String permissionName = permission.getModule().getDescription() + "_" + permission.getName();
                authorities.add(new SimpleGrantedAuthority(permissionName));
            }
        }

        return new CustomUserPrincipal(
                user.getIdUser(),
                user.getUsername(),
                user.getEmail(),
                user.getKey(),
                user.isEnabled(),
                authorities
        );
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return enabled; }
}
