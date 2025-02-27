package secteam12.pai1.salt_model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@Entity
@Table(name = "salts")
public class Salt {

    @Id
	@Column(nullable = false)
	protected Integer id;

    @Column(nullable = false)
    private String salt;

}

