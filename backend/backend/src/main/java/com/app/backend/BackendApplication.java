package com.app.backend;

import com.app.backend.entities.Product;
import com.app.backend.repositories.ProductRepository;
import com.github.javafaker.Faker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.util.UUID;

@SpringBootApplication
@EnableJpaRepositories
public class BackendApplication implements CommandLineRunner {
@Autowired
	ProductRepository productRepository;
	public static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		this.productRepository.deleteAll();

		Faker faker = new Faker();

		for (int i = 0; i < 100; i++) {
			Product product = new Product();
			product.setReference(UUID.randomUUID().toString());
			product.setDesignation(faker.commerce().productName());
			product.setPrix(faker.number().randomDouble(2, 1, 1000));
			product.setQuantite(faker.number().numberBetween(1,1000));

			this.productRepository.save(product);
		}

	}



}
