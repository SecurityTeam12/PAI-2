package secteam12.pai1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import secteam12.pai1.model.Message;

public interface MessageRepository extends JpaRepository<Message,Long>{
    
}
