package secteam12.pai1.model;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.List;


@Getter
@Setter
@Entity
@Table(name = "users")
public class User {

    @Id
    @SequenceGenerator(name = "entity_seq",
            sequenceName = "entity_sequence",
            initialValue = 100)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "entity_seq")
    protected Integer id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String hash;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<Transaction> transactions;


    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", hash='" + hash + '\'' +
                '}';
    }
}