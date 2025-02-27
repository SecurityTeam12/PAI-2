package secteam12.pai1.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import secteam12.pai1.model.User;

import javax.sql.RowSet;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);

    @Query("SELECT COUNT(t) FROM User u JOIN u.transactions t WHERE u.id = :id")
    Integer findUserTransactionLenghtByUserId(Integer id);

    RowSet getByid(Integer id);
}
