package rsa_module.utility;

import java.util.Random;

public class Random_Number_Generator {

	public static double generate_random_double() {
		return generate_random_double(1);
	}
	
	public static double generate_random_double(double scale) {
		return Math.random() * scale;
	}
	public static Random generate_new_random_generator() {
		return new Random();
	}

}
