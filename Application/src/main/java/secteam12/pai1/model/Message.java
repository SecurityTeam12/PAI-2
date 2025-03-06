package secteam12.pai1.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
public class Message {
    @Id
    @SequenceGenerator(name = "entity_seq",
            sequenceName = "entity_sequence",
            initialValue = 100)
    @GeneratedValue(strategy = GenerationType.SEQUENCE	, generator = "entity_seq")
    private Long id;

    @Column(nullable = false)
    private String messageContent;

    @Column(nullable = false)
    private LocalDateTime timestamp = LocalDateTime.now();

    @ManyToOne()
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Override
    public String toString() {
        return "Message{" +
                "id=" + id +
                ", message='" + messageContent + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }

}
