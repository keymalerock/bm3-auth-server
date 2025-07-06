package com.bm3.bm3_auth_server.repository;

import com.bm3.bm3_auth_server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByUsername(String username);

    @Query("SELECT u FROM User u " +
            "LEFT JOIN FETCH u.rolesMtM r " +
            "LEFT JOIN FETCH r.permissions p " +
            "LEFT JOIN FETCH p.module " +
            "WHERE u.username = :username")
    Optional<User> findByUsernameWithRolesAndPermissionsAndModules(@Param("username") String username);
}
