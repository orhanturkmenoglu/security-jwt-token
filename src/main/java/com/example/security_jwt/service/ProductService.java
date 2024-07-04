package com.example.security_jwt.service;

import com.example.security_jwt.model.Product;
import com.example.security_jwt.repository.ProductRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductService {

    private final ProductRepository productRepository;

    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    public List<Product> getProductsAll() {
        return productRepository.findAll();
    }
}
