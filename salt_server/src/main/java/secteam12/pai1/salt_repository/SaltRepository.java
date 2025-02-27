package secteam12.pai1.salt_repository;

import org.springframework.data.jpa.repository.JpaRepository;
import secteam12.pai1.salt_model.Salt;

public interface SaltRepository extends JpaRepository<Salt, Integer> {
    Salt findByid(int id);
    
}
